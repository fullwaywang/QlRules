/**
 * @name linux-f7068114d45ec55996b9040e98111afa56e010fe-sr_do_ioctl
 * @id cpp/linux/f7068114d45ec55996b9040e98111afa56e010fe/sr_do_ioctl
 * @description linux-f7068114d45ec55996b9040e98111afa56e010fe-sr_do_ioctl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and target_0.getDeclarationEntry(1).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_0)
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof PointerFieldAccess
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned char *")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("unsigned char[96]")
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vcgc_186, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="sense"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__memcpy")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sense"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("unsigned char[96]")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="64"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sense"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_3))
}

predicate func_4(Parameter vcgc_186, Variable vSDev_188, Variable vsshdr_189) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="sense"
		and target_4.getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("scsi_execute")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vSDev_188
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cmd"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data_direction"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="buflen"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsshdr_189
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="timeout"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcgc_186
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(Literal).getValue()="3"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(10).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(11).(Literal).getValue()="0")
}

predicate func_5(Parameter vcgc_186) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="timeout"
		and target_5.getQualifier().(VariableAccess).getTarget()=vcgc_186)
}

from Function func, Parameter vcgc_186, Variable vSDev_188, Variable vsshdr_189
where
not func_0(func)
and not func_1(func)
and not func_3(vcgc_186, func)
and func_4(vcgc_186, vSDev_188, vsshdr_189)
and vcgc_186.getType().hasName("packet_command *")
and func_5(vcgc_186)
and vSDev_188.getType().hasName("scsi_device *")
and vsshdr_189.getType().hasName("scsi_sense_hdr")
and vcgc_186.getParentScope+() = func
and vSDev_188.getParentScope+() = func
and vsshdr_189.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
