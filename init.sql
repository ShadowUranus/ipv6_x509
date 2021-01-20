drop table result;
drop table infos;

create table infos
(
    id                     integer primary key autoincrement,
    subject_name           varchar(255),
    issuer_name            varchar(255),
    subject_rfc4514_string varchar(255),
    issuer_rfc4514_string  varchar(255),
    CA                     integer(1) check ( CA in (0, 1) ),
    CRL                    integer(1) check ( CRL in (0, 1) ),
    self_signature         integer(1) check ( self_signature in (0, 1) ),
    serial_number          varchar(255),
    version                varchar(255),
    unique (subject_rfc4514_string, issuer_rfc4514_string, serial_number)
);
create table result
(
    file_name              varchar(255),
    subject_rfc4514_string varchar(255),
    issuer_rfc4514_string  varchar(255),
    error_type             varchar(255),
    error_detail           varchar(255),
    cert_id                integer,
    foreign key (cert_id) references infos(id),
    unique (file_name, subject_rfc4514_string, issuer_rfc4514_string, error_type, error_detail)
)