/**
 * @name postgresql-37a795a60-coerce_type
 * @id cpp/postgresql/37a795a60/coerce-type
 * @description postgresql-37a795a60-src/backend/parser/parse_coerce.c-coerce_type CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtargetTypeId_157, FunctionCall target_0) {
		target_0.getTarget().hasName("typeidTypeRelid")
		and not target_0.getTarget().hasName("typeOrDomainTypeRelid")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtargetTypeId_157
}

predicate func_1(Parameter vinputTypeId_157, FunctionCall target_1) {
		target_1.getTarget().hasName("typeidTypeRelid")
		and not target_1.getTarget().hasName("typeOrDomainTypeRelid")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vinputTypeId_157
}

predicate func_2(Parameter vnode_156, Parameter vinputTypeId_157, Parameter vlocation_158, LogicalOrExpr target_3, ExprStmt target_4, FunctionCall target_5, FunctionCall target_6, ExprStmt target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("Oid")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinputTypeId_157
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="location"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("RelabelType *")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlocation_158
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnode_156
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("RelabelType *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(VariableAccess).getLocation())
		and target_6.getArgument(5).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vinputTypeId_157, Parameter vtargetTypeId_157, LogicalOrExpr target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("typeInheritsFrom")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinputTypeId_157
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtargetTypeId_157
		and target_3.getAnOperand().(FunctionCall).getTarget().hasName("typeIsOfTypedTable")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinputTypeId_157
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtargetTypeId_157
}

predicate func_4(Parameter vnode_156, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="arg"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ConvertRowtypeExpr *")
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnode_156
}

predicate func_5(Parameter vinputTypeId_157, FunctionCall target_5) {
		target_5.getTarget().hasName("format_type_be")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vinputTypeId_157
}

predicate func_6(Parameter vnode_156, Parameter vtargetTypeId_157, Parameter vlocation_158, FunctionCall target_6) {
		target_6.getTarget().hasName("coerce_record_to_complex")
		and target_6.getArgument(0).(VariableAccess).getTarget().getType().hasName("ParseState *")
		and target_6.getArgument(1).(VariableAccess).getTarget()=vnode_156
		and target_6.getArgument(2).(VariableAccess).getTarget()=vtargetTypeId_157
		and target_6.getArgument(3).(VariableAccess).getTarget().getType().hasName("CoercionContext")
		and target_6.getArgument(4).(VariableAccess).getTarget().getType().hasName("CoercionForm")
		and target_6.getArgument(5).(VariableAccess).getTarget()=vlocation_158
}

predicate func_7(Parameter vlocation_158, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="location"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ConvertRowtypeExpr *")
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlocation_158
}

from Function func, Parameter vnode_156, Parameter vinputTypeId_157, Parameter vtargetTypeId_157, Parameter vlocation_158, FunctionCall target_0, FunctionCall target_1, LogicalOrExpr target_3, ExprStmt target_4, FunctionCall target_5, FunctionCall target_6, ExprStmt target_7
where
func_0(vtargetTypeId_157, target_0)
and func_1(vinputTypeId_157, target_1)
and not func_2(vnode_156, vinputTypeId_157, vlocation_158, target_3, target_4, target_5, target_6, target_7)
and func_3(vinputTypeId_157, vtargetTypeId_157, target_3)
and func_4(vnode_156, target_4)
and func_5(vinputTypeId_157, target_5)
and func_6(vnode_156, vtargetTypeId_157, vlocation_158, target_6)
and func_7(vlocation_158, target_7)
and vnode_156.getType().hasName("Node *")
and vinputTypeId_157.getType().hasName("Oid")
and vtargetTypeId_157.getType().hasName("Oid")
and vlocation_158.getType().hasName("int")
and vnode_156.getFunction() = func
and vinputTypeId_157.getFunction() = func
and vtargetTypeId_157.getFunction() = func
and vlocation_158.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
