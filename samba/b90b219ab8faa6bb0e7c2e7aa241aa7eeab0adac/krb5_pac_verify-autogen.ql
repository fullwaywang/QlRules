/**
 * @name samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-krb5_pac_verify
 * @id cpp/samba/b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac/krb5-pac-verify
 * @description samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-lib/krb5/pac.c-krb5_pac_verify CVE-2022-42898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpac_1243, AddressOfExpr target_9, SubExpr target_10) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="offset"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="server_checksum"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpac_1243, SubExpr target_10, SubExpr target_11) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="offset"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="privsvr_checksum"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpac_1243, PointerArithmeticOperation target_12, SubExpr target_13) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="offset"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="server_checksum"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vpac_1243, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="server_checksum"
		and target_3.getQualifier().(VariableAccess).getTarget()=vpac_1243
}

predicate func_4(Parameter vpac_1243, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="privsvr_checksum"
		and target_4.getQualifier().(VariableAccess).getTarget()=vpac_1243
}

predicate func_5(Parameter vpac_1243, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="server_checksum"
		and target_5.getQualifier().(VariableAccess).getTarget()=vpac_1243
}

predicate func_6(Parameter vpac_1243, AddressOfExpr target_9, SubExpr target_10, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="offset_lo"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="server_checksum"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_7(Parameter vpac_1243, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="offset_lo"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="privsvr_checksum"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
}

predicate func_8(Parameter vpac_1243, PointerArithmeticOperation target_12, SubExpr target_13, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="offset_lo"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="server_checksum"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_9(Parameter vpac_1243, AddressOfExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
}

predicate func_10(Parameter vpac_1243, SubExpr target_10) {
		target_10.getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="server_checksum"
		and target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_10.getRightOperand().(Literal).getValue()="4"
}

predicate func_11(Parameter vpac_1243, SubExpr target_11) {
		target_11.getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_11.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="privsvr_checksum"
		and target_11.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_11.getRightOperand().(Literal).getValue()="4"
}

predicate func_12(Parameter vpac_1243, PointerArithmeticOperation target_12) {
		target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset_lo"
		and target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="server_checksum"
		and target_12.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_12.getAnOperand().(Literal).getValue()="4"
}

predicate func_13(Parameter vpac_1243, SubExpr target_13) {
		target_13.getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="server_checksum"
		and target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpac_1243
		and target_13.getRightOperand().(Literal).getValue()="4"
}

from Function func, Parameter vpac_1243, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, AddressOfExpr target_9, SubExpr target_10, SubExpr target_11, PointerArithmeticOperation target_12, SubExpr target_13
where
not func_0(vpac_1243, target_9, target_10)
and not func_1(vpac_1243, target_10, target_11)
and not func_2(vpac_1243, target_12, target_13)
and func_3(vpac_1243, target_3)
and func_4(vpac_1243, target_4)
and func_5(vpac_1243, target_5)
and func_6(vpac_1243, target_9, target_10, target_6)
and func_7(vpac_1243, target_7)
and func_8(vpac_1243, target_12, target_13, target_8)
and func_9(vpac_1243, target_9)
and func_10(vpac_1243, target_10)
and func_11(vpac_1243, target_11)
and func_12(vpac_1243, target_12)
and func_13(vpac_1243, target_13)
and vpac_1243.getType().hasName("const krb5_pac")
and vpac_1243.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
