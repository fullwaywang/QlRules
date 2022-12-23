/**
 * @name linux-0625b4ba1a5d4703c7fb01c497bd6c156908af00-create_qp_common
 * @id cpp/linux/0625b4ba1a5d4703c7fb01c497bd6c156908af00/create_qp_common
 * @description linux-0625b4ba1a5d4703c7fb01c497bd6c156908af00-create_qp_common 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and target_0.getExpr().getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
