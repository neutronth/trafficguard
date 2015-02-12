
#ifndef _TRANSACTION_HOLDER_H
#define _TRANSACTION_HOLDER_H

#include <atomic>
#include <memory>
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
                     function<void (shared_ptr<TransactionHolder>, string)> cb)
    : transaction_ (&transaction), destroy_ (false), callback_ (cb) {}

  ~TransactionHolder () {}

  Transaction *getTransaction () { return transaction_; }

  function<void (shared_ptr<TransactionHolder>, string)> getCallback ()
  {
    return callback_;
  }

  void destroy () { destroy_ = true; } 
  bool isDestroy () { return destroy_; }
  
private:
  Transaction  *transaction_;
  atomic<bool>  destroy_;
  function<void (shared_ptr<TransactionHolder>, string)> callback_;
};

}

#endif // _TRANSACTION_HOLDER_H
