#include "ScimClient.h"
#include <QsLog.h>
#include "AppVersionQliqDirect.h"

const QString SCIM_PATH = "/scimv2";

ScimClient::ScimClient(QObject *parent) :
    BaseRestClient(Module::Scim, parent)
{
    setUserAgent("qliqDirect " APP_VERSION_NAME);
}

void ScimClient::setWebServerAddress(const QString &address)
{
    m_webServerAddress = address;
}

void ScimClient::setApiKey(const QString &apiKey)
{
    m_apiKey = apiKey;
    setAuthorizationHeader("Basic " + apiKey);
}

QNetworkReply *ScimClient::sendRequest(HttpMethod method, const QString &serverPath, RequestType type, const QString &json, const QVariant &callerData, const QByteArray& file)
{
    QUrl url(m_webServerAddress + serverPath);
    OptionalRequestParams optionalParams;
    optionalParams.requestType = type;
    optionalParams.callerData = callerData;
    return BaseRestClient::sendRequest(method, url, json, Callback(), file, optionalParams);
}

void ScimClient::createUser(const QString &json, const QVariant& callerData, const QByteArray& avatar)
{
    sendRequest(HttpMethod::Post, SCIM_PATH + "/Users", CreateUserRequestType, json, callerData, avatar);
}

void ScimClient::getUser(const QString &qliqId, const QVariant &callerData)
{
    sendRequest(HttpMethod::Get, SCIM_PATH + "/Users/" + qliqId, GetUserRequestType, "", callerData);
}

void ScimClient::updateUser(const QString& qliqId, const QString &json, const QVariant &callerData, const QByteArray& avatar)
{
    sendRequest(HttpMethod::Put, SCIM_PATH + "/Users/" + qliqId, UpdateUserRequestType, json, callerData, avatar);
}

void ScimClient::deleteUser(const QString& qliqId, const QVariant &callerData)
{
    sendRequest(HttpMethod::Delete, SCIM_PATH + "/Users/" + qliqId, DeleteUserRequestType, "", callerData);
}

void ScimClient::createGroup(const QString &json, const QVariant &localData)
{
    sendRequest(HttpMethod::Post, SCIM_PATH + "/Groups", CreateGroupRequestType, json, localData);
}

void ScimClient::getGroup(const QString &qliqId, const QVariant &callerData)
{
    sendRequest(HttpMethod::Get, SCIM_PATH + "/Groups/" + qliqId, GetGroupRequestType, "", callerData);
}

void ScimClient::updateGroup(const QString &qliqId, const QString &json, const QVariant &callerData)
{
    sendRequest(HttpMethod::Put, SCIM_PATH + "/Groups/" + qliqId, UpdateGroupRequestType, json, callerData);
}

void ScimClient::deleteGroup(const QString &qliqId, const QVariant &callerData)
{
    sendRequest(HttpMethod::Delete, SCIM_PATH + "/Groups/" + qliqId, DeleteGroupRequestType, "", callerData);
}

QVector<int> ScimClient::permanentErrors()
{
    static QVector<int> errors = QVector<int>()
        << 400  // bad request, when server doesn't like the JSON syntax or some of the values
        << 422 // same as above, not documented by sent by server (at least in the past)
        << 404; // means cloud-deleted

    return errors;
}

void ScimClient::onRequestFinished(const RestError &error, const QString& response, unsigned int requestType, const QVariant &callerData)
{
    int httpStatusCode = error.httpStatus ? error.httpStatus : -error.networkError;

    switch (error.httpStatus)  {
    case 404:
        httpStatusCode = error.httpStatus;
        break;
        //409 Conflict	The request could not be completed because of a conflict.
        // resource is already present/created, so conflict occurs.
    case 409:
        httpStatusCode = error.httpStatus;
        break;
    default:
        break;
    }

    switch (requestType) {
    case CreateUserRequestType:
        emit createUserFinished(httpStatusCode, response, callerData);
        break;
    case GetUserRequestType:
        emit getUserFinished(httpStatusCode, response, callerData);
        break;
    case UpdateUserRequestType:
        emit updateUserFinished(httpStatusCode, response, callerData);
        break;
    case DeleteUserRequestType:
        emit deleteUserFinished(httpStatusCode, response, callerData);
        break;

    case CreateGroupRequestType:
        emit createGroupFinished(httpStatusCode, response, callerData);
        break;
    case GetGroupRequestType:
        emit getGroupFinished(httpStatusCode, response, callerData);
        break;
    case UpdateGroupRequestType:
        emit updateGroupFinished(httpStatusCode, response, callerData);
        break;
    case DeleteGroupRequestType:
        emit deleteGroupFinished(httpStatusCode, response, callerData);
        break;

    default:
        QLOG_ERROR() << "ScimClient::replyFinished(): internal error, not supported RequestType: " << requestType << "response:" << response;
        break;
    }
}

bool ScimClient::isNetworkError(int httpStatusCode)
{
    return httpStatusCode < 100;
}
