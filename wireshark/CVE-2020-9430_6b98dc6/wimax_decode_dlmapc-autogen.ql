/**
 * @name wireshark-6b98dc63701b1da1cc7681cb383dabb0b7007d73-wimax_decode_dlmapc
 * @id cpp/wireshark/6b98dc63701b1da1cc7681cb383dabb0b7007d73/wimax-decode-dlmapc
 * @description wireshark-6b98dc63701b1da1cc7681cb383dabb0b7007d73-plugins/epan/wimax/msg_dlmap.c-wimax_decode_dlmapc CVE-2020-9430
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_1, Function func) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(SizeofExprOperator).getValue()="4"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(SizeofExprOperator).getValue()="4"
}

from Function func, RelationalOperation target_1
where
not func_0(target_1, func)
and func_1(target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
