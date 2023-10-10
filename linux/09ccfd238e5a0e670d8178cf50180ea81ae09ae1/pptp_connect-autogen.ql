/**
 * @name linux-09ccfd238e5a0e670d8178cf50180ea81ae09ae1-pptp_connect
 * @id cpp/linux/09ccfd238e5a0e670d8178cf50180ea81ae09ae1/pptp_connect
 * @description linux-09ccfd238e5a0e670d8178cf50180ea81ae09ae1-pptp_connect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsockaddr_len_433, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsockaddr_len_433
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getValue()="30"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

from Function func, Parameter vsockaddr_len_433
where
not func_0(vsockaddr_len_433, func)
and vsockaddr_len_433.getType().hasName("int")
and vsockaddr_len_433.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
