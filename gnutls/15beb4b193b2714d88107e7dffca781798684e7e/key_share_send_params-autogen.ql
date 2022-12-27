/**
 * @name gnutls-15beb4b193b2714d88107e7dffca781798684e7e-key_share_send_params
 * @id cpp/gnutls/15beb4b193b2714d88107e7dffca781798684e7e/key-share-send-params
 * @description gnutls-15beb4b193b2714d88107e7dffca781798684e7e-key_share_send_params CVE-2021-20231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(VariableDeclarationEntry target_0 |
		target_0.getType() instanceof IntType
		and target_0.getDeclaration().getParentScope+() = func)
}

predicate func_1(Variable vcur_length_668) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vcur_length_668
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue() instanceof PointerFieldAccess)
}

predicate func_2(Variable vcur_length_668) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vcur_length_668)
}

predicate func_3(Parameter vextdata_663) {
	exists(SubExpr target_3 |
		target_3.getLeftOperand().(SubExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_3.getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_3.getRightOperand().(Literal).getValue()="2"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_write_uint16")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vextdata_663
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("unsigned int"))
}

predicate func_5(Parameter vextdata_663) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="length"
		and target_5.getQualifier().(VariableAccess).getTarget()=vextdata_663
		and target_5.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vextdata_663)
}

predicate func_7(Function func) {
	exists(DeclStmt target_7 |
		target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Parameter vextdata_663, Variable vlengthp_667) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getTarget()=vlengthp_667
		and target_8.getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_8.getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vextdata_663
		and target_8.getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset() instanceof PointerFieldAccess)
}

predicate func_9(Parameter vsession_662, Parameter vextdata_663, Variable vlengthp_667, Variable vcur_length_668) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("_gnutls_write_uint16")
		and target_9.getExpr().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_9.getExpr().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vextdata_663
		and target_9.getExpr().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vcur_length_668
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlengthp_667
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="entity"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="security_parameters"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_662
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1")
}

from Function func, Parameter vsession_662, Parameter vextdata_663, Variable vlengthp_667, Variable vcur_length_668
where
func_0(func)
and func_1(vcur_length_668)
and func_2(vcur_length_668)
and not func_3(vextdata_663)
and func_5(vextdata_663)
and func_7(func)
and func_8(vextdata_663, vlengthp_667)
and func_9(vsession_662, vextdata_663, vlengthp_667, vcur_length_668)
and vsession_662.getType().hasName("gnutls_session_t")
and vextdata_663.getType().hasName("gnutls_buffer_st *")
and vlengthp_667.getType().hasName("unsigned char *")
and vsession_662.getParentScope+() = func
and vextdata_663.getParentScope+() = func
and vlengthp_667.getParentScope+() = func
and vcur_length_668.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
