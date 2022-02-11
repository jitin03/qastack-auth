package service

import (
	"github.com/hashicorp/go-hclog"
	"github.com/jitin07/qastackauth/utils"
	"github.com/labstack/gommon/log"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// MailService represents the interface for our mail service.
type MailService interface {
	CreateMail(mailReq *Mail) []byte
	SendMail(mailReq *Mail) error
	NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail
}

type MailType int

// List of Mail Types we are going to send.
const (
	MailConfirmation MailType = iota + 1
	PassReset
)

// MailData represents the data to be sent to the template of the mail.
type MailData struct {
	Email string
	Code  string
}

// Mail represents a email request
type Mail struct {
	from    string
	to      []string
	subject string
	body    string
	mtype   MailType
	data    *MailData
}

// SGMailService is the sendgrid implementation of our MailService.
type SGMailService struct {
	logger  hclog.Logger
	configs *utils.Configurations
}

// NewSGMailService returns a new instance of SGMailService
func NewSGMailService(logger hclog.Logger, configs *utils.Configurations) *SGMailService {
	return &SGMailService{logger, configs}
}

// CreateMail takes in a mail request and constructs a sendgrid mail type.
func (ms *SGMailService) CreateMail(mailReq *Mail) []byte {

	m := mail.NewV3Mail()

	from := mail.NewEmail("qastack", mailReq.from)
	m.SetFrom(from)

	if mailReq.mtype == MailConfirmation {
		m.SetTemplateID(ms.configs.MailVerifTemplateID)
	} else if mailReq.mtype == PassReset {
		m.SetTemplateID(ms.configs.PassResetTemplateID)
	}

	p := mail.NewPersonalization()

	tos := make([]*mail.Email, 0)
	for _, to := range mailReq.to {
		tos = append(tos, mail.NewEmail("user", to))
	}

	p.AddTos(tos...)
	log.Info(mailReq.data.Email)
	p.SetDynamicTemplateData("Email", mailReq.data.Email)
	p.SetDynamicTemplateData("Code", mailReq.data.Code)

	m.AddPersonalizations(p)
	return mail.GetRequestBody(m)
}

// SendMail creates a sendgrid mail from the given mail request and sends it.
func (ms *SGMailService) SendMail(mailReq *Mail) error {

	request := sendgrid.GetRequest("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", "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	var Body = ms.CreateMail(mailReq)
	request.Body = Body
	ms.logger.Debug(string(request.Body))
	response, err := sendgrid.API(request)
	if err != nil {
		ms.logger.Error("unable to send mail", "error", err)
		return err
	}
	ms.logger.Info("mail sent successfully", response.Body, response.StatusCode)
	return nil
}

// NewMail returns a new mail request.
func (ms *SGMailService) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	return &Mail{
		from:    from,
		to:      to,
		subject: subject,
		mtype:   mailType,
		data:    data,
	}
}
