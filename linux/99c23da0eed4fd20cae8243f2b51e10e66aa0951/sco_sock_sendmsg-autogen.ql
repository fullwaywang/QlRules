/**
 * @name linux-99c23da0eed4fd20cae8243f2b51e10e66aa0951-sco_sock_sendmsg
 * @id cpp/linux/99c23da0eed4fd20cae8243f2b51e10e66aa0951/sco_sock_sendmsg
 * @description linux-99c23da0eed4fd20cae8243f2b51e10e66aa0951-sco_sock_sendmsg CVE-2021-3640
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof VoidPointerType
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_1(Parameter vlen_725, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("void *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("kmalloc")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlen_725
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="3264"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1))
}

predicate func_4(Parameter vmsg_724, Parameter vlen_725, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(FunctionCall).getTarget().hasName("memcpy_from_msg")
		and target_4.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("void *")
		and target_4.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmsg_724
		and target_4.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_725
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("void *")
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-14"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_4))
}

predicate func_7(Parameter vmsg_724, Parameter vlen_725, Variable vsk_727, Variable verr_728, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition() instanceof EqualityOperation
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_728
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sco_send_frame")
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_727
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("void *")
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_725
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="msg_flags"
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_724
		and target_7.getElse() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_7))
}

predicate func_13(Variable vsk_727, Variable verr_728) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_728
		and target_13.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-107"
		and target_13.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="107"
		and target_13.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="skc_state"
		and target_13.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_13.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_727)
}

predicate func_16(Parameter vmsg_724) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="msg_flags"
		and target_16.getQualifier().(VariableAccess).getTarget()=vmsg_724)
}

from Function func, Parameter vmsg_724, Parameter vlen_725, Variable vsk_727, Variable verr_728
where
not func_0(func)
and not func_1(vlen_725, func)
and not func_4(vmsg_724, vlen_725, func)
and not func_7(vmsg_724, vlen_725, vsk_727, verr_728, func)
and func_13(vsk_727, verr_728)
and vmsg_724.getType().hasName("msghdr *")
and func_16(vmsg_724)
and vlen_725.getType().hasName("size_t")
and vsk_727.getType().hasName("sock *")
and verr_728.getType().hasName("int")
and vmsg_724.getParentScope+() = func
and vlen_725.getParentScope+() = func
and vsk_727.getParentScope+() = func
and verr_728.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
