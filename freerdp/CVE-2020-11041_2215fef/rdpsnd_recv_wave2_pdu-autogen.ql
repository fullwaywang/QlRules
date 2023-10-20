/**
 * @name freerdp-2215fef975b963b3995356c3583f0e87cd08ac6b-rdpsnd_recv_wave2_pdu
 * @id cpp/freerdp/2215fef975b963b3995356c3583f0e87cd08ac6b/rdpsnd-recv-wave2-pdu
 * @description freerdp-2215fef975b963b3995356c3583f0e87cd08ac6b-channels/rdpsnd/client/rdpsnd_main.c-rdpsnd_recv_wave2_pdu CVE-2020-11041
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwFormatNo_615, Parameter vrdpsnd_613, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwFormatNo_615
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="NumberOfClientFormats"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_613
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vwFormatNo_615, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwFormatNo_615
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_2(Variable vwFormatNo_615, Parameter vrdpsnd_613, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ClientFormats"
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_613
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vwFormatNo_615
}

predicate func_3(Parameter vrdpsnd_613, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cBlockNo"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_613
		and target_3.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
}

predicate func_4(Parameter vrdpsnd_613, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="waveDataSize"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_613
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="12"
}

from Function func, Variable vwFormatNo_615, Parameter vrdpsnd_613, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vwFormatNo_615, vrdpsnd_613, target_1, target_2, target_3, target_4, func)
and func_1(vwFormatNo_615, target_1)
and func_2(vwFormatNo_615, vrdpsnd_613, target_2)
and func_3(vrdpsnd_613, target_3)
and func_4(vrdpsnd_613, target_4)
and vwFormatNo_615.getType().hasName("UINT16")
and vrdpsnd_613.getType().hasName("rdpsndPlugin *")
and vwFormatNo_615.getParentScope+() = func
and vrdpsnd_613.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
