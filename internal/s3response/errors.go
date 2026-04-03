package s3response

import (
	"encoding/xml"
	"net/http"

	"github.com/google/uuid"
)

type ErrorCode int

const (
	ErrNone ErrorCode = iota
	ErrAccessDenied
	ErrBucketAlreadyExists
	ErrBucketAlreadyOwnedByYou
	ErrBucketNotEmpty
	ErrInternalError
	ErrInvalidBucketName
	ErrInvalidPart
	ErrInvalidPartOrder
	ErrMalformedXML
	ErrNoSuchBucket
	ErrNoSuchKey
	ErrNoSuchUpload
	ErrSignatureDoesNotMatch
	ErrRequestTimeTooSkewed
	ErrInvalidAccessKeyID
	ErrMissingFields
	ErrMethodNotAllowed
	ErrInvalidArgument
	ErrEntityTooLarge
)

type APIError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

var errorCodeMap = map[ErrorCode]APIError{
	ErrAccessDenied: {
		Code:           "AccessDenied",
		Description:    "Access Denied.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrBucketAlreadyExists: {
		Code:           "BucketAlreadyExists",
		Description:    "The requested bucket name is not available.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrBucketAlreadyOwnedByYou: {
		Code:           "BucketAlreadyOwnedByYou",
		Description:    "Your previous request to create the named bucket succeeded and you already own it.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrBucketNotEmpty: {
		Code:           "BucketNotEmpty",
		Description:    "The bucket you tried to delete is not empty.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrInternalError: {
		Code:           "InternalError",
		Description:    "We encountered an internal error, please try again.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
	ErrInvalidBucketName: {
		Code:           "InvalidBucketName",
		Description:    "The specified bucket is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPart: {
		Code:           "InvalidPart",
		Description:    "One or more of the specified parts could not be found.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPartOrder: {
		Code:           "InvalidPartOrder",
		Description:    "The list of parts was not in ascending order.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedXML: {
		Code:           "MalformedXML",
		Description:    "The XML you provided was not well-formed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNoSuchBucket: {
		Code:           "NoSuchBucket",
		Description:    "The specified bucket does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNoSuchKey: {
		Code:           "NoSuchKey",
		Description:    "The specified key does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNoSuchUpload: {
		Code:           "NoSuchUpload",
		Description:    "The specified multipart upload does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrSignatureDoesNotMatch: {
		Code:           "SignatureDoesNotMatch",
		Description:    "The request signature we calculated does not match the signature you provided.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrRequestTimeTooSkewed: {
		Code:           "RequestTimeTooSkewed",
		Description:    "The difference between the request time and the server's time is too large.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidAccessKeyID: {
		Code:           "InvalidAccessKeyId",
		Description:    "The AWS access key ID you provided does not exist in our records.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrMissingFields: {
		Code:           "MissingFields",
		Description:    "Missing required fields in the request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMethodNotAllowed: {
		Code:           "MethodNotAllowed",
		Description:    "The specified method is not allowed against this resource.",
		HTTPStatusCode: http.StatusMethodNotAllowed,
	},
	ErrInvalidArgument: {
		Code:           "InvalidArgument",
		Description:    "Invalid argument.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEntityTooLarge: {
		Code:           "EntityTooLarge",
		Description:    "Your proposed upload exceeds the maximum allowed size.",
		HTTPStatusCode: http.StatusBadRequest,
	},
}

// S3ErrorResponse is the XML error response (NO namespace on Error element)
type S3ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

func GetAPIError(code ErrorCode) APIError {
	if e, ok := errorCodeMap[code]; ok {
		return e
	}
	return errorCodeMap[ErrInternalError]
}

func WriteError(w http.ResponseWriter, r *http.Request, code ErrorCode) {
	apiErr := GetAPIError(code)
	WriteErrorCustom(w, r, apiErr.HTTPStatusCode, apiErr.Code, apiErr.Description)
}

func WriteErrorCustom(w http.ResponseWriter, r *http.Request, statusCode int, code, message string) {
	requestID := uuid.New().String()
	resource := r.URL.Path

	resp := S3ErrorResponse{
		Code:      code,
		Message:   message,
		Resource:  resource,
		RequestID: requestID,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("Server", "S3Gateway")
	w.WriteHeader(statusCode)

	xml.NewEncoder(w).Encode(resp)
}

func WriteXML(w http.ResponseWriter, statusCode int, v interface{}) {
	requestID := uuid.New().String()
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("Server", "S3Gateway")
	w.WriteHeader(statusCode)
	w.Write([]byte(xml.Header))
	xml.NewEncoder(w).Encode(v)
}
