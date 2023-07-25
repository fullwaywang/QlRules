/**
 * @name varnish-c5fd097e5cce8b461c6443af02b3448baef2491d-http_isfiltered
 * @id cpp/varnish/c5fd097e5cce8b461c6443af02b3448baef2491d/http-isfiltered
 * @description varnish-c5fd097e5cce8b461c6443af02b3448baef2491d-bin/varnishd/cache/cache_http.c-http_isfiltered CVE-2022-38150
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vu_1143, BitwiseAndExpr target_1, ArrayExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vu_1143
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vu_1143, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdf"
		and target_1.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vu_1143
		and target_1.getRightOperand().(BinaryBitwiseOperation).getValue()="1"
}

predicate func_2(Parameter vu_1143, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vu_1143
}

from Function func, Parameter vu_1143, BitwiseAndExpr target_1, ArrayExpr target_2
where
not func_0(vu_1143, target_1, target_2, func)
and func_1(vu_1143, target_1)
and func_2(vu_1143, target_2)
and vu_1143.getType().hasName("unsigned int")
and vu_1143.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
