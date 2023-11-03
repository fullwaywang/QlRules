/**
 * @name curl-9889db043393092e9d4b5a42720bba0b3d58deba-ldap_recv
 * @id cpp/curl/9889db043393092e9d4b5a42720bba0b3d58deba/ldap-recv
 * @description curl-9889db043393092e9d4b5a42720bba0b3d58deba-lib/openldap.c-ldap_recv CVE-2018-1000121
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbvals_476, BlockStmt target_7, AddressOfExpr target_2) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(VariableAccess).getTarget()=vbvals_476
		and target_0.getParent().(ForStmt).getStmt()=target_7
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbvals_476, Variable vbvp_476, ArrayExpr target_8) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vbvals_476
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ldap_get_attribute_ber")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ld"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ldapconninfo *")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("LDAPMessage *")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("BerElement *")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("berval")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbvp_476
		and target_1.getOperand().(VariableAccess).getLocation().isBefore(target_8.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbvals_476, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vbvals_476
}

predicate func_3(Variable vrc_450, BlockStmt target_7, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vrc_450
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(ForStmt).getStmt()=target_7
}

predicate func_5(Variable vbvp_476, AssignExpr target_10, VariableAccess target_5) {
		target_5.getTarget()=vbvp_476
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ldap_get_attribute_ber")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ld"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ldapconninfo *")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("LDAPMessage *")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("BerElement *")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("berval")
		and target_5.getLocation().isBefore(target_10.getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
}

predicate func_6(Variable vbvp_476, ExprStmt target_11, VariableAccess target_6) {
		target_6.getTarget()=vbvp_476
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ldap_get_attribute_ber")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ld"
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ldapconninfo *")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("LDAPMessage *")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("BerElement *")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("berval")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_6.getLocation())
}

predicate func_7(BlockStmt target_7) {
		target_7.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="bv_val"
		and target_7.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("berval")
		and target_7.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="bv_len"
		and target_7.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("berval")
		and target_7.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="7"
		and target_7.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_7.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="7"
		and target_7.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=";binary"
		and target_7.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_7.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vbvals_476, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget()=vbvals_476
		and target_8.getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_10(Variable vrc_450, Variable vbvp_476, AssignExpr target_10) {
		target_10.getLValue().(VariableAccess).getTarget()=vrc_450
		and target_10.getRValue().(FunctionCall).getTarget().hasName("ldap_get_attribute_ber")
		and target_10.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ld"
		and target_10.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ldapconninfo *")
		and target_10.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("LDAPMessage *")
		and target_10.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("BerElement *")
		and target_10.getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("berval")
		and target_10.getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbvp_476
}

predicate func_11(Variable vrc_450, Variable vbvp_476, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_450
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ldap_get_attribute_ber")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ld"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ldapconninfo *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("LDAPMessage *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("BerElement *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("berval")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbvp_476
}

from Function func, Variable vrc_450, Variable vbvals_476, Variable vbvp_476, AddressOfExpr target_2, EqualityOperation target_3, VariableAccess target_5, VariableAccess target_6, BlockStmt target_7, ArrayExpr target_8, AssignExpr target_10, ExprStmt target_11
where
not func_0(vbvals_476, target_7, target_2)
and not func_1(vbvals_476, vbvp_476, target_8)
and func_2(vbvals_476, target_2)
and func_3(vrc_450, target_7, target_3)
and func_5(vbvp_476, target_10, target_5)
and func_6(vbvp_476, target_11, target_6)
and func_7(target_7)
and func_8(vbvals_476, target_8)
and func_10(vrc_450, vbvp_476, target_10)
and func_11(vrc_450, vbvp_476, target_11)
and vrc_450.getType().hasName("int")
and vbvals_476.getType().hasName("berval *")
and vbvp_476.getType().hasName("berval **")
and vrc_450.(LocalVariable).getFunction() = func
and vbvals_476.(LocalVariable).getFunction() = func
and vbvp_476.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
