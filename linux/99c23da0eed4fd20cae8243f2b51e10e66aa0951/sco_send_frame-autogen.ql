/**
 * @name linux-99c23da0eed4fd20cae8243f2b51e10e66aa0951-sco_send_frame
 * @id cpp/linux/99c23da0eed4fd20cae8243f2b51e10e66aa0951/sco_send_frame
 * @description linux-99c23da0eed4fd20cae8243f2b51e10e66aa0951-sco_send_frame CVE-2021-3640
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Parameter vlen_283) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("__memcpy")
		and target_1.getArgument(0) instanceof FunctionCall
		and target_1.getArgument(1).(VariableAccess).getType().hasName("void *")
		and target_1.getArgument(2).(VariableAccess).getTarget()=vlen_283)
}

predicate func_2(Parameter vlen_283, Variable vskb_286) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("skb_put")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vskb_286
		and target_2.getArgument(1).(VariableAccess).getTarget()=vlen_283)
}

predicate func_4(Parameter vmsg_283) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="msg_flags"
		and target_4.getQualifier().(VariableAccess).getTarget()=vmsg_283)
}

predicate func_5(Parameter vmsg_283, Parameter vlen_283, Variable vskb_286, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(FunctionCall).getTarget().hasName("memcpy_from_msg")
		and target_5.getCondition().(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_5.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmsg_283
		and target_5.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_283
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_286
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-14"
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

from Function func, Parameter vmsg_283, Parameter vlen_283, Variable vskb_286
where
not func_1(vlen_283)
and func_2(vlen_283, vskb_286)
and func_4(vmsg_283)
and func_5(vmsg_283, vlen_283, vskb_286, func)
and vmsg_283.getType().hasName("msghdr *")
and vlen_283.getType().hasName("int")
and vskb_286.getType().hasName("sk_buff *")
and vmsg_283.getParentScope+() = func
and vlen_283.getParentScope+() = func
and vskb_286.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
