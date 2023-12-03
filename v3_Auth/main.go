// From DataWire Example service as base

package main

// NOTE: VERY WIP, DOES NOT WORK YET

import (
	"context"
	"log"
	"net/http"
	"net/url"
//	"strconv"
//	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	envoyCoreV3 "github.com/datawire/ambassador/v2/pkg/api/envoy/config/core/v3"
	envoyAuthV3 "github.com/datawire/ambassador/v2/pkg/api/envoy/service/auth/v3"
	envoyType "github.com/datawire/ambassador/v2/pkg/api/envoy/type/v3"

	"github.com/datawire/dlib/dhttp"
//        "encoding/json"
//	"fmt"
	"strings"
        "encoding/base64"
        "regexp"
)

func main() {
	grpcHandler := grpc.NewServer()
	envoyAuthV3.RegisterAuthorizationServer(grpcHandler, &AuthService{})

	sc := &dhttp.ServerConfig{
		Handler: grpcHandler,
	}

	log.Print("starting...")
	log.Fatal(sc.ListenAndServe(context.Background(), ":3000"))
}

type AuthService struct{}

func (s *AuthService) Check(ctx context.Context, req *envoyAuthV3.CheckRequest) (*envoyAuthV3.CheckResponse, error) {
	log.Println("ACCESS",
		req.GetAttributes().GetRequest().GetHttp().GetMethod(),
		req.GetAttributes().GetRequest().GetHttp().GetHost(),
		req.GetAttributes().GetRequest().GetHttp().GetBody(),
	)
	log.Println("~~~~~~~~> REQUEST BODY ~~~~~~~~>", req.GetAttributes().GetRequest().GetHttp().GetBody())
	log.Println("~~~~~~~~> REQUEST RAW BODY ~~~~~~~~>", req.GetAttributes().GetRequest().GetHttp().GetRawBody())
	log.Println("~~~~~~~~> REQUEST HTTP ~~~~~~~~>", req.GetAttributes().GetRequest().GetHttp())
	log.Println("~~~~~~~~> REQUEST ~~~~~~~~>", req.GetAttributes().GetRequest())
	requestURI, err := url.ParseRequestURI(req.GetAttributes().GetRequest().GetHttp().GetPath())
	if err != nil {
		log.Println("=> ERROR", err)
		return &envoyAuthV3.CheckResponse{
			Status: &status.Status{Code: int32(code.Code_UNKNOWN)},
			HttpResponse: &envoyAuthV3.CheckResponse_DeniedResponse{
				DeniedResponse: &envoyAuthV3.DeniedHttpResponse{
					Status: &envoyType.HttpStatus{Code: http.StatusInternalServerError},
					Headers: []*envoyCoreV3.HeaderValueOption{
						{Header: &envoyCoreV3.HeaderValue{Key: "Content-Type", Value: "application/json"}},
					},
					Body: `{"msg": "internal server error"}`,
				},
			},
		}, nil
	}
	log.Println("RequestURI: ", requestURI)

	// Read over and log the headers for the request
	hasCert := false
        certInfo := make(map[string]string)
	log.Println("|~~~~~~~~~~~~ BEGIN HEADERS ~~~~~~~~~~~~|")
	for k, v := range req.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		log.Printf("%s: %s", k, v)
		// Sleep for x seconds when this header is present
		if k == "x-forwarded-client-cert" {
                  hasCert = true
                  log.Println("Found header x-forwarded-client-cert")
                  entries := strings.Split(v, ";")
	          for _, e := range entries {
		    parts := strings.SplitN(e, "=", 2)
                    elem := parts[1]
		    if len(elem) > 0 && elem[0] == '"' {
			elem = elem[1:]
		    }
		    if len(elem) > 0 && elem[len(elem)-1] == '"' {
			elem = elem[:len(elem)-1]
		    }
                    parts[1] = elem
		    certInfo[parts[0]] = parts[1]
                    if parts[0] == "Cert" {
			//fmt.Println(url.QueryUnescape(certInfo[parts[0]]))
			certPem, _ := url.QueryUnescape(certInfo[parts[0]])
			certInfo[parts[0]] = base64.StdEncoding.EncodeToString([]byte(certPem))
		    }
	          }
                  //jsonString, _ := json.Marshal(certInfo)
	          //fmt.Println(string(jsonString))
                }
	}
	log.Println("|~~~~~~~~~~~~ END HEADERS ~~~~~~~~~~~~|")

        match_est, _ := regexp.MatchString(".well-known/est", requestURI.Path)
        match_bootstrap, _ := regexp.MatchString("/api/bootstrap", requestURI.Path)
        match_quote, _ := regexp.MatchString("/quote", requestURI.Path)

	if (match_bootstrap || match_est || match_quote ) && ! hasCert {
	  log.Println("=> DENIED REQUEST", err)
          return &envoyAuthV3.CheckResponse{
	    Status: &status.Status{Code: int32(code.Code_PERMISSION_DENIED)},
	    HttpResponse: &envoyAuthV3.CheckResponse_DeniedResponse{
	      DeniedResponse: &envoyAuthV3.DeniedHttpResponse{
	        Status: &envoyType.HttpStatus{Code: http.StatusForbidden},
		Headers: []*envoyCoreV3.HeaderValueOption{
		  {Header: &envoyCoreV3.HeaderValue{Key: "Content-Type", Value: "application/json"}},
		},
		Body: `{"msg": "Your request was denied, unauthorized"}`,
	      },
	    },
	  }, nil
	}

	log.Print("=> ALLOW REQUEST")
        if (hasCert) {
	  return &envoyAuthV3.CheckResponse{
	    Status: &status.Status{Code: int32(code.Code_OK)},
	      HttpResponse: &envoyAuthV3.CheckResponse_OkResponse{
	        OkResponse: &envoyAuthV3.OkHttpResponse{
		  Headers: []*envoyCoreV3.HeaderValueOption{
		    {
		      Header: &envoyCoreV3.HeaderValue{Key: "X-ARR-ClientCert", Value: certInfo["Cert"]},
		      Append: &wrappers.BoolValue{Value: false},
		    },
		    {
		      Header: &envoyCoreV3.HeaderValue{Key: "Content-Type", Value: "application/pkcs10"},
		      Append: &wrappers.BoolValue{Value: false},
		    },
                    {
		      Header: &envoyCoreV3.HeaderValue{Key: "Content-Transfer-Encoding", Value: "base64"},
		      Append: &wrappers.BoolValue{Value: false},
		    },
		  },
		},
	      },
	  }, nil
        }

        return &envoyAuthV3.CheckResponse{
          Status: &status.Status{Code: int32(code.Code_OK)},
          HttpResponse: &envoyAuthV3.CheckResponse_OkResponse{
            OkResponse: &envoyAuthV3.OkHttpResponse{
              Headers: []*envoyCoreV3.HeaderValueOption{
              },
            },
          },
        }, nil

}
