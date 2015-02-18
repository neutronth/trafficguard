
#ifndef _TRANSACTION_HOLDER_H
#define _TRANSACTION_HOLDER_H

#include <memory>
#include <atomic>
#include <functional>
#include <atscppapi/Transaction.h>

using namespace atscppapi;
using std::atomic;
using std::shared_ptr;
using std::function;

namespace TrafficGuard {

extern Logger tg_log;

class TransactionHolder
{
public:
  TransactionHolder (Transaction &transaction,
                     shared_ptr<Mutex> mtx,
                     function<void (shared_ptr<TransactionHolder>, string)> cb)
    : transaction_ (&transaction), mutex_ (mtx), destroy_ (false),
      callback_ (cb) {}

  ~TransactionHolder () {}

  Transaction *getTransaction () { return transaction_; }
  shared_ptr<Mutex> getMutex () { return mutex_; }

  void setTransactionDestroyed () { destroy_ = true; }
  bool isTransactionDestroyed () { return destroy_; }

  function<void (shared_ptr<TransactionHolder>, string)> getCallback ()
  {
    return callback_;
  }

private:
  Transaction  *transaction_;
  shared_ptr<Mutex> mutex_;
  atomic<bool>      destroy_;
  function<void (shared_ptr<TransactionHolder>, string)> callback_;
};

}

#endif // _TRANSACTION_HOLDER_H
