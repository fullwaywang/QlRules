/**
 * @name linux-c518adafa39f37858697ac9309c6cf1805581446-vsock_poll
 * @id cpp/linux/c518adafa39f37858697ac9309c6cf1805581446/vsock_poll
 * @description linux-c518adafa39f37858697ac9309c6cf1805581446-vsock_poll 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsock_972, Variable vtransport_1017) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtransport_1017
		and target_0.getExpr().(AssignExpr).getRValue() instanceof PointerFieldAccess
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_972)
}

predicate func_1(Variable vvsk_977) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="transport"
		and target_1.getQualifier().(VariableAccess).getTarget()=vvsk_977)
}

predicate func_2(Function func) {
	exists(Initializer target_2 |
		target_2.getExpr() instanceof PointerFieldAccess
		and target_2.getExpr().getEnclosingFunction() = func)
}

predicate func_3(Variable vsk_975, Variable vmask_976, Variable vvsk_977, Variable vtransport_1017, Variable vdata_ready_now_1030, Variable vret_1031) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vtransport_1017
		and target_3.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="stream_is_active"
		and target_3.getAnOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtransport_1017
		and target_3.getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vvsk_977
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="sk_shutdown"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_975
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="notify_poll_in"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtransport_1017
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vvsk_977
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdata_ready_now_1030
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_1031
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vmask_976
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="8"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vdata_ready_now_1030
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vmask_976
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64")
}

from Function func, Parameter vsock_972, Variable vsk_975, Variable vmask_976, Variable vvsk_977, Variable vtransport_1017, Variable vdata_ready_now_1030, Variable vret_1031
where
not func_0(vsock_972, vtransport_1017)
and func_1(vvsk_977)
and func_2(func)
and vsock_972.getType().hasName("socket *")
and vvsk_977.getType().hasName("vsock_sock *")
and vtransport_1017.getType().hasName("const vsock_transport *")
and func_3(vsk_975, vmask_976, vvsk_977, vtransport_1017, vdata_ready_now_1030, vret_1031)
and vdata_ready_now_1030.getType().hasName("bool")
and vret_1031.getType().hasName("int")
and vsock_972.getParentScope+() = func
and vsk_975.getParentScope+() = func
and vmask_976.getParentScope+() = func
and vvsk_977.getParentScope+() = func
and vtransport_1017.getParentScope+() = func
and vdata_ready_now_1030.getParentScope+() = func
and vret_1031.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
