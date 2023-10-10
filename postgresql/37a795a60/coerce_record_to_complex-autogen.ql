/**
 * @name postgresql-37a795a60-coerce_record_to_complex
 * @id cpp/postgresql/37a795a60/coerce-record-to-complex
 * @description postgresql-37a795a60-src/backend/parser/parse_coerce.c-coerce_record_to_complex CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtargetTypeId_963, Variable vrowexpr_968, VariableAccess target_0) {
		target_0.getTarget()=vtargetTypeId_963
		and vtargetTypeId_963.getIndex() = 2
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="row_typeid"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrowexpr_968
}

predicate func_1(Parameter vtargetTypeId_963, FunctionCall target_8, FunctionCall target_9) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("Oid")
		and target_1.getRValue().(FunctionCall).getTarget().hasName("getBaseTypeAndTypmod")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtargetTypeId_963
		and target_1.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int32")
		and target_8.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vtupdesc_969, RelationalOperation target_11, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupdesc_969
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_rowtype_tupdesc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int32")
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_2)
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vtargetTypeId_963, Parameter vccontext_964, Parameter vcformat_965, Parameter vlocation_966, Variable vrowexpr_968, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ReturnStmt target_16, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("Oid")
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtargetTypeId_963
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="row_format"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrowexpr_968
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("coerce_to_domain")
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrowexpr_968
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("Oid")
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int32")
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtargetTypeId_963
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vccontext_964
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcformat_965
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vlocation_966
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_5)
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vtargetTypeId_963, UnaryMinusExpr target_6) {
		target_6.getValue()="-1"
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_rowtype_tupdesc")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtargetTypeId_963
}

/*predicate func_7(Parameter vtargetTypeId_963, VariableAccess target_7) {
		target_7.getTarget()=vtargetTypeId_963
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_rowtype_tupdesc")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
}

*/
predicate func_8(Parameter vtargetTypeId_963, FunctionCall target_8) {
		target_8.getTarget().hasName("format_type_be")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vtargetTypeId_963
}

predicate func_9(Parameter vtargetTypeId_963, FunctionCall target_9) {
		target_9.getTarget().hasName("format_type_be")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vtargetTypeId_963
}

predicate func_11(Variable vtupdesc_969, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_11.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_11.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtupdesc_969
}

predicate func_12(Parameter vtargetTypeId_963, Variable vrowexpr_968, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="row_typeid"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrowexpr_968
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtargetTypeId_963
}

predicate func_13(Parameter vccontext_964, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Node *")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("coerce_to_target_type")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ParseState *")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Node *")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="atttypid"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_attribute")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_attribute")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vccontext_964
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(UnaryMinusExpr).getValue()="-1"
}

predicate func_14(Parameter vcformat_965, Variable vrowexpr_968, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="row_format"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrowexpr_968
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcformat_965
}

predicate func_15(Parameter vlocation_966, Variable vrowexpr_968, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="location"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrowexpr_968
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlocation_966
}

predicate func_16(Variable vrowexpr_968, ReturnStmt target_16) {
		target_16.getExpr().(VariableAccess).getTarget()=vrowexpr_968
}

from Function func, Parameter vtargetTypeId_963, Parameter vccontext_964, Parameter vcformat_965, Parameter vlocation_966, Variable vrowexpr_968, Variable vtupdesc_969, VariableAccess target_0, UnaryMinusExpr target_6, FunctionCall target_8, FunctionCall target_9, RelationalOperation target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ReturnStmt target_16
where
func_0(vtargetTypeId_963, vrowexpr_968, target_0)
and not func_1(vtargetTypeId_963, target_8, target_9)
and not func_2(vtupdesc_969, target_11, func)
and not func_5(vtargetTypeId_963, vccontext_964, vcformat_965, vlocation_966, vrowexpr_968, target_12, target_13, target_14, target_15, target_16, func)
and func_6(vtargetTypeId_963, target_6)
and func_8(vtargetTypeId_963, target_8)
and func_9(vtargetTypeId_963, target_9)
and func_11(vtupdesc_969, target_11)
and func_12(vtargetTypeId_963, vrowexpr_968, target_12)
and func_13(vccontext_964, target_13)
and func_14(vcformat_965, vrowexpr_968, target_14)
and func_15(vlocation_966, vrowexpr_968, target_15)
and func_16(vrowexpr_968, target_16)
and vtargetTypeId_963.getType().hasName("Oid")
and vccontext_964.getType().hasName("CoercionContext")
and vcformat_965.getType().hasName("CoercionForm")
and vlocation_966.getType().hasName("int")
and vrowexpr_968.getType().hasName("RowExpr *")
and vtupdesc_969.getType().hasName("TupleDesc")
and vtargetTypeId_963.getFunction() = func
and vccontext_964.getFunction() = func
and vcformat_965.getFunction() = func
and vlocation_966.getFunction() = func
and vrowexpr_968.(LocalVariable).getFunction() = func
and vtupdesc_969.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
