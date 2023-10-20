/**
 * @name postgresql-37a795a60-transformAssignmentIndirection
 * @id cpp/postgresql/37a795a60/transformAssignmentIndirection
 * @description postgresql-37a795a60-src/backend/parser/parse_target.c-transformAssignmentIndirection CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtargetTypeId_680, VariableAccess target_0) {
		target_0.getTarget()=vtargetTypeId_680
		and vtargetTypeId_680.getIndex() = 4
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("typeidTypeRelid")
}

predicate func_1(Parameter vtargetTypeId_680, Variable vfstore_727, VariableAccess target_1) {
		target_1.getTarget()=vtargetTypeId_680
		and vtargetTypeId_680.getIndex() = 4
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resulttype"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfstore_727
}

predicate func_2(Parameter vtargetTypMod_681, EqualityOperation target_5, FunctionCall target_6, FunctionCall target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int32")
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtargetTypMod_681
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(10)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getArgument(4).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vtargetTypeId_680, EqualityOperation target_5, FunctionCall target_6, ExprStmt target_8) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("Oid")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("getBaseTypeAndTypmod")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtargetTypeId_680
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int32")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(11)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getArgument(3).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vtargetTypeId_680, Parameter vlocation_685, Variable vfstore_727, EqualityOperation target_5, ExprStmt target_9, FunctionCall target_7, ExprStmt target_10, ReturnStmt target_11) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("Oid")
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtargetTypeId_680
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("coerce_to_domain")
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfstore_727
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("Oid")
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int32")
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtargetTypeId_680
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vlocation_685
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(24)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getArgument(3).(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getLocation().isBefore(target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation())
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(VariableAccess).getLocation()))
}

predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Node *")
}

predicate func_6(Parameter vtargetTypeId_680, Parameter vtargetTypMod_681, Parameter vlocation_685, FunctionCall target_6) {
		target_6.getTarget().hasName("transformAssignmentSubscripts")
		and target_6.getArgument(0).(VariableAccess).getTarget().getType().hasName("ParseState *")
		and target_6.getArgument(1).(VariableAccess).getTarget().getType().hasName("Node *")
		and target_6.getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_6.getArgument(3).(VariableAccess).getTarget()=vtargetTypeId_680
		and target_6.getArgument(4).(VariableAccess).getTarget()=vtargetTypMod_681
		and target_6.getArgument(5).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_6.getArgument(6).(VariableAccess).getTarget().getType().hasName("List *")
		and target_6.getArgument(7).(VariableAccess).getTarget().getType().hasName("bool")
		and target_6.getArgument(8).(VariableAccess).getTarget().getType().hasName("ListCell *")
		and target_6.getArgument(9).(VariableAccess).getTarget().getType().hasName("Node *")
		and target_6.getArgument(10).(VariableAccess).getTarget()=vlocation_685
}

predicate func_7(Parameter vtargetTypeId_680, Parameter vtargetTypMod_681, Parameter vlocation_685, FunctionCall target_7) {
		target_7.getTarget().hasName("transformAssignmentSubscripts")
		and target_7.getArgument(0).(VariableAccess).getTarget().getType().hasName("ParseState *")
		and target_7.getArgument(1).(VariableAccess).getTarget().getType().hasName("Node *")
		and target_7.getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_7.getArgument(3).(VariableAccess).getTarget()=vtargetTypeId_680
		and target_7.getArgument(4).(VariableAccess).getTarget()=vtargetTypMod_681
		and target_7.getArgument(5).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_7.getArgument(6).(VariableAccess).getTarget().getType().hasName("List *")
		and target_7.getArgument(7).(VariableAccess).getTarget().getType().hasName("bool")
		and target_7.getArgument(8).(Literal).getValue()="0"
		and target_7.getArgument(9).(VariableAccess).getTarget().getType().hasName("Node *")
		and target_7.getArgument(10).(VariableAccess).getTarget()=vlocation_685
}

predicate func_8(Parameter vtargetTypeId_680, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Oid")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("typeidTypeRelid")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtargetTypeId_680
}

predicate func_9(Parameter vtargetTypeId_680, Variable vfstore_727, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resulttype"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfstore_727
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtargetTypeId_680
}

predicate func_10(Parameter vlocation_685, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Node *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("transformAssignmentIndirection")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ParseState *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="str"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Node *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("int32")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="next"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ListCell *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("Node *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vlocation_685
}

predicate func_11(Variable vfstore_727, ReturnStmt target_11) {
		target_11.getExpr().(VariableAccess).getTarget()=vfstore_727
}

from Function func, Parameter vtargetTypeId_680, Parameter vtargetTypMod_681, Parameter vlocation_685, Variable vfstore_727, VariableAccess target_0, VariableAccess target_1, EqualityOperation target_5, FunctionCall target_6, FunctionCall target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ReturnStmt target_11
where
func_0(vtargetTypeId_680, target_0)
and func_1(vtargetTypeId_680, vfstore_727, target_1)
and not func_2(vtargetTypMod_681, target_5, target_6, target_7)
and not func_3(vtargetTypeId_680, target_5, target_6, target_8)
and not func_4(vtargetTypeId_680, vlocation_685, vfstore_727, target_5, target_9, target_7, target_10, target_11)
and func_5(target_5)
and func_6(vtargetTypeId_680, vtargetTypMod_681, vlocation_685, target_6)
and func_7(vtargetTypeId_680, vtargetTypMod_681, vlocation_685, target_7)
and func_8(vtargetTypeId_680, target_8)
and func_9(vtargetTypeId_680, vfstore_727, target_9)
and func_10(vlocation_685, target_10)
and func_11(vfstore_727, target_11)
and vtargetTypeId_680.getType().hasName("Oid")
and vtargetTypMod_681.getType().hasName("int32")
and vlocation_685.getType().hasName("int")
and vfstore_727.getType().hasName("FieldStore *")
and vtargetTypeId_680.getFunction() = func
and vtargetTypMod_681.getFunction() = func
and vlocation_685.getFunction() = func
and vfstore_727.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
