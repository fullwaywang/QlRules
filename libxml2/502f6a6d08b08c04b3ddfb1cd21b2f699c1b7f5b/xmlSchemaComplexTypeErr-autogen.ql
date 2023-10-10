/**
 * @name libxml2-502f6a6d08b08c04b3ddfb1cd21b2f699c1b7f5b-xmlSchemaComplexTypeErr
 * @id cpp/libxml2/502f6a6d08b08c04b3ddfb1cd21b2f699c1b7f5b/xmlSchemaComplexTypeErr
 * @description libxml2-502f6a6d08b08c04b3ddfb1cd21b2f699c1b7f5b-xmlschemas.c-xmlSchemaComplexTypeErr CVE-2016-4448
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstr_2538, ExprStmt target_2, ExprStmt target_3) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlEscapeFormatString")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vstr_2538
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrcat")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstr_2538
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vstr_2538, EqualityOperation target_4, VariableAccess target_1) {
		target_1.getTarget()=vstr_2538
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrcat")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_1.getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vstr_2538, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstr_2538
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrcat")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr_2538
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" ).\n"
}

predicate func_3(Variable vstr_2538, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrcat")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstr_2538
}

predicate func_4(Variable vstr_2538, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vstr_2538
		and target_4.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vstr_2538, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_4
where
not func_0(vstr_2538, target_2, target_3)
and func_1(vstr_2538, target_4, target_1)
and func_2(vstr_2538, target_2)
and func_3(vstr_2538, target_3)
and func_4(vstr_2538, target_4)
and vstr_2538.getType().hasName("xmlChar *")
and vstr_2538.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
