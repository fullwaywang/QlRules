/**
 * @name linux-5233252fce714053f0151680933571a2da9cbfb4-sco_sock_bind
 * @id cpp/linux/5233252fce714053f0151680933571a2da9cbfb4/sco_sock_bind
 * @description linux-5233252fce714053f0151680933571a2da9cbfb4-sco_sock_bind 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vaddr_len_518, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vaddr_len_518
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getValue()="8"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

from Function func, Parameter vaddr_len_518
where
not func_0(vaddr_len_518, func)
and vaddr_len_518.getType().hasName("int")
and vaddr_len_518.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
