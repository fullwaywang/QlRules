/**
 * @name linux-4b81ccebaeee885ab1aa1438133f2991e3a2b6ea-__bpf_ringbuf_reserve
 * @id cpp/linux/4b81ccebaeee885ab1aa1438133f2991e3a2b6ea/--bpf-ringbuf-reserve
 * @description linux-4b81ccebaeee885ab1aa1438133f2991e3a2b6ea-__bpf_ringbuf_reserve 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_311, Parameter vrb_308, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_311
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="mask"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrb_308
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsize_308, Variable vlen_311) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vlen_311
		and target_1.getRValue().(AddExpr).getAnOperand().(BitwiseOrExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_308
		and target_1.getRValue().(AddExpr).getAnOperand().(BitwiseOrExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getRValue().(AddExpr).getAnOperand().(BitwiseOrExpr).getRightOperand().(SubExpr).getValue()="7"
		and target_1.getRValue().(AddExpr).getAnOperand().(BitwiseOrExpr).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="8"
		and target_1.getRValue().(AddExpr).getAnOperand().(BitwiseOrExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1")
}

from Function func, Parameter vsize_308, Variable vlen_311, Parameter vrb_308
where
not func_0(vlen_311, vrb_308, func)
and vlen_311.getType().hasName("u32")
and func_1(vsize_308, vlen_311)
and vrb_308.getType().hasName("bpf_ringbuf *")
and vsize_308.getParentScope+() = func
and vlen_311.getParentScope+() = func
and vrb_308.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
