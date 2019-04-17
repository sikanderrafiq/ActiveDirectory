#ifndef SCIMCLIENT_H
#define SCIMCLIENT_H
#include "service/BaseRestClient.h"


class ScimClient : public BaseRestClient {
    Q_OBJECT
public:
    enum HttpResponseCode {
        OkResponseCode = 200,
        CreatedResponseCode = 201,
        BadRequestResponseCode = 400,
        NotFoundResponseCode = 404,
        ConflictResponseCode = 409,
        MandatoryFieldMissingResponseCode = 422 // not in standard, returned by qliq server
    };

    ScimClient(QObject *parent = 0);

    void setWebServerAddress(const QString& address);
    void setApiKey(const QString& apiKey);

    void createUser(const QString& json, const QVariant& callerData, const QByteArray& avatar = QByteArray());
    void getUser(const QString& qliqId, const QVariant& callerData);
    void updateUser(const QString& qliqId, const QString& json, const QVariant& callerData, const QByteArray& avatar = QByteArray());
    void deleteUser(const QString& qliqId, const QVariant& callerData);

    void createGroup(const QString& json, const QVariant& localData);
    void getGroup(const QString& qliqId, const QVariant& callerData);
    void updateGroup(const QString& qliqId, const QString& json, const QVariant& callerData);
    void deleteGroup(const QString& qliqId, const QVariant& callerData);

    static bool isNetworkError(int httpStatusCode);
    /// Returns list of errors that mean the request content is invalid so it shouldn't be resent unless
    /// data changes in AD.
    static QVector<int> permanentErrors();

signals:
    void createUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void getUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void updateUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void deleteUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);

    void createGroupFinished(int httpStatusCode, const  QString& response, const QVariant& localData);
    void getGroupFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void updateGroupFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void deleteGroupFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);

protected:
    virtual void onRequestFinished(const RestError& error, const QString& response, unsigned int requestType, const QVariant& callerData) override;

private:
    enum RequestType {
        CreateUserRequestType,
        GetUserRequestType,
        UpdateUserRequestType,
        DeleteUserRequestType,

        CreateGroupRequestType,
        GetGroupRequestType,
        UpdateGroupRequestType,
        DeleteGroupRequestType
    };

    QNetworkReply *sendRequest(HttpMethod method, const QString& path, RequestType type, const QString& json, const QVariant& callerData, const QByteArray& file = QByteArray());

    QString m_webServerAddress;
    QString m_apiKey;
};

#endif // SCIMCLIENT_H
