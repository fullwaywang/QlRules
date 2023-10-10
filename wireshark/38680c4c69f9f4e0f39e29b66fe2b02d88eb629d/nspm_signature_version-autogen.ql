/**
 * @name wireshark-38680c4c69f9f4e0f39e29b66fe2b02d88eb629d-nspm_signature_version
 * @id cpp/wireshark/38680c4c69f9f4e0f39e29b66fe2b02d88eb629d/nspm-signature-version
 * @description wireshark-38680c4c69f9f4e0f39e29b66fe2b02d88eb629d-wiretap/netscaler.c-nspm_signature_version CVE-2019-10895
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vdp_847, LogicalAndExpr target_3, NotExpr target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sig_Signature"
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_847
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="sig_RecordSize"
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_847
		and target_1.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlen_845, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="257"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_845
}

predicate func_3(Parameter vlen_845, Variable vdp_847, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sig_RecordType"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_847
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="sig_RecordSize"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_847
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_845
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="31"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_845
}

predicate func_4(Variable vdp_847, NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("nspm_signature_isv20")
		and target_4.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sig_Signature"
		and target_4.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_847
}

from Function func, Parameter vlen_845, Variable vdp_847, LogicalAndExpr target_2, LogicalAndExpr target_3, NotExpr target_4
where
not func_0(func)
and not func_1(vdp_847, target_3, target_4)
and func_2(vlen_845, target_2)
and func_3(vlen_845, vdp_847, target_3)
and func_4(vdp_847, target_4)
and vlen_845.getType().hasName("gint32")
and vdp_847.getType().hasName("gchar *")
and vlen_845.getParentScope+() = func
and vdp_847.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
