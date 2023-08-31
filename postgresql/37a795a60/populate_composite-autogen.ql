/**
 * @name postgresql-37a795a60-populate_composite
 * @id cpp/postgresql/37a795a60/populate-composite
 * @description postgresql-37a795a60-src/backend/utils/adt/jsonfuncs.c-populate_composite CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vio_2709, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="tdtypeid"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
}

predicate func_1(Parameter vio_2709, FunctionCall target_1) {
		target_1.getTarget().hasName("FreeTupleDesc")
		and not target_1.getTarget().hasName("update_cached_tupdesc")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
}

predicate func_2(Variable voldcxt_2726, VariableAccess target_2) {
		target_2.getTarget()=voldcxt_2726
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="0"
		and not target_3.getValue()="2249"
		and target_3.getParent().(GEExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vtupdesc_2725, FunctionCall target_4) {
		target_4.getTarget().hasName("DecrTupleDescRefCount")
		and not target_4.getTarget().hasName("domain_check")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vtupdesc_2725
}

predicate func_7(Function func) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getType().hasName("Datum")
		and target_7.getRValue() instanceof Literal
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getType().hasName("Datum")
		and target_8.getRValue() instanceof FunctionCall
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vio_2709, Parameter vtypid_2710, ExprStmt target_40, LogicalOrExpr target_27, FunctionCall target_41) {
	exists(LogicalAndExpr target_9 |
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_2710
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="base_typid"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_2710
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2249"
		and target_9.getParent().(IfStmt).getThen()=target_40
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_41.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_13(Parameter vio_2709, LogicalOrExpr target_27) {
	exists(AddressOfExpr target_13 |
		target_13.getOperand().(PointerFieldAccess).getTarget().getName()="domain_info"
		and target_13.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_15(Function func, DeclStmt target_15) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Function func, DeclStmt target_16) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Parameter vjsv_2715, Variable vjso_2718, Function func, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("JsValueToJsObject")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjsv_2715
		and target_17.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vjso_2718
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Parameter vio_2709, Parameter vmcxt_2713, Parameter vdefaultval_2714, Variable vtuple_2717, Variable vjso_2718, Function func, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtuple_2717
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("populate_record")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="record_io"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdefaultval_2714
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmcxt_2713
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vjso_2718
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

predicate func_19(Variable vjso_2718, Function func, DoStmt target_19) {
		target_19.getCondition().(Literal).getValue()="0"
		and target_19.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="is_json"
		and target_19.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vjso_2718
		and target_19.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hash_destroy")
		and target_19.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="json_hash"
		and target_19.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Variable vtuple_2717, FunctionCall target_20) {
		target_20.getTarget().hasName("HeapTupleHeaderGetDatum")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vtuple_2717
}

predicate func_21(Parameter vio_2709, VariableAccess target_21) {
		target_21.getTarget()=vio_2709
}

predicate func_22(Parameter vio_2709, VariableAccess target_22) {
		target_22.getTarget()=vio_2709
}

predicate func_23(Parameter vio_2709, VariableAccess target_23) {
		target_23.getTarget()=vio_2709
}

predicate func_24(Parameter vtypid_2710, VariableAccess target_24) {
		target_24.getTarget()=vtypid_2710
		and target_24.getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_25(Parameter vmcxt_2713, VariableAccess target_25) {
		target_25.getTarget()=vmcxt_2713
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_27(Parameter vio_2709, Parameter vtypid_2710, Parameter vtypmod_2711, BlockStmt target_42, LogicalOrExpr target_27) {
		target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tdtypeid"
		and target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypid_2710
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tdtypmod"
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypmod_2711
		and target_27.getParent().(IfStmt).getThen()=target_42
}

/*predicate func_28(Parameter vio_2709, PointerFieldAccess target_28) {
		target_28.getTarget().getName()="tdtypmod"
		and target_28.getQualifier().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_28.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
}

*/
/*predicate func_29(Parameter vtypmod_2711, FunctionCall target_41, VariableAccess target_29) {
		target_29.getTarget()=vtypmod_2711
		and target_29.getLocation().isBefore(target_41.getArgument(1).(VariableAccess).getLocation())
}

*/
predicate func_31(LogicalOrExpr target_27, Function func, DeclStmt target_31) {
		target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
		and target_31.getEnclosingFunction() = func
}

predicate func_32(Parameter vio_2709, LogicalOrExpr target_27, ExprStmt target_40, PointerFieldAccess target_32) {
		target_32.getTarget().getName()="tupdesc"
		and target_32.getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_27.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_32.getQualifier().(VariableAccess).getLocation())
}

predicate func_33(Parameter vio_2709, IfStmt target_43, VariableAccess target_33) {
		target_33.getTarget()=vio_2709
		and target_33.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_43.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_33.getLocation())
}

predicate func_34(Parameter vmcxt_2713, Variable voldcxt_2726, AssignExpr target_34) {
		target_34.getLValue().(VariableAccess).getTarget()=voldcxt_2726
		and target_34.getRValue().(FunctionCall).getTarget().hasName("MemoryContextSwitchTo")
		and target_34.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmcxt_2713
}

predicate func_35(Parameter vio_2709, Variable vtupdesc_2725, AssignExpr target_35) {
		target_35.getLValue().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_35.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_35.getRValue().(FunctionCall).getTarget().hasName("CreateTupleDescCopy")
		and target_35.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtupdesc_2725
}

predicate func_36(Variable voldcxt_2726, LogicalOrExpr target_27, ExprStmt target_36) {
		target_36.getExpr().(FunctionCall).getTarget().hasName("MemoryContextSwitchTo")
		and target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voldcxt_2726
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
}

predicate func_37(Variable vtupdesc_2725, LogicalOrExpr target_27, DoStmt target_37) {
		target_37.getCondition() instanceof Literal
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tdrefcount"
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtupdesc_2725
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
}

/*predicate func_38(Variable vtupdesc_2725, IfStmt target_38) {
		target_38.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tdrefcount"
		and target_38.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtupdesc_2725
		and target_38.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_38.getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

*/
predicate func_40(ExprStmt target_40) {
		target_40.getExpr() instanceof FunctionCall
}

predicate func_41(Parameter vtypid_2710, Parameter vtypmod_2711, FunctionCall target_41) {
		target_41.getTarget().hasName("lookup_rowtype_tupdesc")
		and target_41.getArgument(0).(VariableAccess).getTarget()=vtypid_2710
		and target_41.getArgument(1).(VariableAccess).getTarget()=vtypmod_2711
}

predicate func_42(Parameter vio_2709, BlockStmt target_42) {
		target_42.getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_42.getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_42.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_42.getStmt(3).(ExprStmt).getExpr() instanceof AssignExpr
		and target_42.getStmt(4).(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_43(Parameter vio_2709, IfStmt target_43) {
		target_43.getCondition().(PointerFieldAccess).getTarget().getName()="tupdesc"
		and target_43.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_2709
		and target_43.getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

from Function func, Parameter vio_2709, Parameter vtypid_2710, Parameter vtypmod_2711, Parameter vmcxt_2713, Parameter vdefaultval_2714, Parameter vjsv_2715, Variable vtuple_2717, Variable vjso_2718, Variable vtupdesc_2725, Variable voldcxt_2726, PointerFieldAccess target_0, FunctionCall target_1, VariableAccess target_2, Literal target_3, FunctionCall target_4, DeclStmt target_15, DeclStmt target_16, ExprStmt target_17, ExprStmt target_18, DoStmt target_19, FunctionCall target_20, VariableAccess target_21, VariableAccess target_22, VariableAccess target_23, VariableAccess target_24, VariableAccess target_25, LogicalOrExpr target_27, DeclStmt target_31, PointerFieldAccess target_32, VariableAccess target_33, AssignExpr target_34, AssignExpr target_35, ExprStmt target_36, DoStmt target_37, ExprStmt target_40, FunctionCall target_41, BlockStmt target_42, IfStmt target_43
where
func_0(vio_2709, target_0)
and func_1(vio_2709, target_1)
and func_2(voldcxt_2726, target_2)
and func_3(func, target_3)
and func_4(vtupdesc_2725, target_4)
and not func_7(func)
and not func_8(func)
and not func_9(vio_2709, vtypid_2710, target_40, target_27, target_41)
and not func_13(vio_2709, target_27)
and func_15(func, target_15)
and func_16(func, target_16)
and func_17(vjsv_2715, vjso_2718, func, target_17)
and func_18(vio_2709, vmcxt_2713, vdefaultval_2714, vtuple_2717, vjso_2718, func, target_18)
and func_19(vjso_2718, func, target_19)
and func_20(vtuple_2717, target_20)
and func_21(vio_2709, target_21)
and func_22(vio_2709, target_22)
and func_23(vio_2709, target_23)
and func_24(vtypid_2710, target_24)
and func_25(vmcxt_2713, target_25)
and func_27(vio_2709, vtypid_2710, vtypmod_2711, target_42, target_27)
and func_31(target_27, func, target_31)
and func_32(vio_2709, target_27, target_40, target_32)
and func_33(vio_2709, target_43, target_33)
and func_34(vmcxt_2713, voldcxt_2726, target_34)
and func_35(vio_2709, vtupdesc_2725, target_35)
and func_36(voldcxt_2726, target_27, target_36)
and func_37(vtupdesc_2725, target_27, target_37)
and func_40(target_40)
and func_41(vtypid_2710, vtypmod_2711, target_41)
and func_42(vio_2709, target_42)
and func_43(vio_2709, target_43)
and vio_2709.getType().hasName("CompositeIOData *")
and vtypid_2710.getType().hasName("Oid")
and vtypmod_2711.getType().hasName("int32")
and vmcxt_2713.getType().hasName("MemoryContext")
and vdefaultval_2714.getType().hasName("HeapTupleHeader")
and vjsv_2715.getType().hasName("JsValue *")
and vtuple_2717.getType().hasName("HeapTupleHeader")
and vjso_2718.getType().hasName("JsObject")
and vtupdesc_2725.getType().hasName("TupleDesc")
and voldcxt_2726.getType().hasName("MemoryContext")
and vio_2709.getFunction() = func
and vtypid_2710.getFunction() = func
and vtypmod_2711.getFunction() = func
and vmcxt_2713.getFunction() = func
and vdefaultval_2714.getFunction() = func
and vjsv_2715.getFunction() = func
and vtuple_2717.(LocalVariable).getFunction() = func
and vjso_2718.(LocalVariable).getFunction() = func
and vtupdesc_2725.(LocalVariable).getFunction() = func
and voldcxt_2726.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
