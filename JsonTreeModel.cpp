#include <QtGui>
#include <list>
#include "JsonTreeModel.h"

VariantMapModel::VariantMapModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

VariantMapModel::~VariantMapModel()
{

}

void VariantMapModel::setHeaders(const QStringList &headers)
{
    beginResetModel();
    m_headers = headers;
    endResetModel();
}

void VariantMapModel::setDataAndHeaders(const QVariantList &data)
{
    beginResetModel();
    m_data = data;
    if (m_data.size() > 0) {
        QVariantMap firstRow = m_data.at(0).toMap();
        for (QVariantMap::const_iterator iter = firstRow.begin(); iter != firstRow.end(); ++iter) {
            m_headers.push_back(iter.key());
        }
        qSort(m_headers);
    } else {
        m_headers.clear();
    }
    endResetModel();
}

void VariantMapModel::setData(const QVariantList &data)
{
    beginResetModel();
    m_data = data;
    endResetModel();
}

void VariantMapModel::appendRow(const QVariantMap &row)
{
    beginInsertRows(QModelIndex(), m_data.size(), m_data.size());
    m_data.append(row);
    endInsertRows();
}

QVariantList VariantMapModel::data() const
{
    return m_data;
}

int VariantMapModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return m_headers.size();
}

QVariant VariantMapModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    if (role != Qt::DisplayRole)
        return QVariant();

    return m_data.at(index.row()).toMap().value(m_headers.at(index.column()));
}

Qt::ItemFlags VariantMapModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}

QVariant VariantMapModel::headerData(int section, Qt::Orientation orientation,
                               int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        return m_headers.at(section);
    } else {
        return QVariant();
    }
}

int VariantMapModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return m_data.size();
}
