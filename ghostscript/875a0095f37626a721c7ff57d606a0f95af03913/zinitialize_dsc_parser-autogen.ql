/**
 * @name ghostscript-875a0095f37626a721c7ff57d606a0f95af03913-zinitialize_dsc_parser
 * @id cpp/ghostscript/875a0095f37626a721c7ff57d606a0f95af03913/zinitialize-dsc-parser
 * @description ghostscript-875a0095f37626a721c7ff57d606a0f95af03913-psi/zdscpars.c-zinitialize_dsc_parser CVE-2016-7979
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Variable vop_152, ValueFieldAccess target_7, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_3.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_3.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_152
		and target_3.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(AddExpr).getValue()="16160"
		and target_3.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(AddExpr).getValue()="544"
		and target_3.getThen().(ReturnStmt).getExpr().(ConditionalExpr).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getThen().(ReturnStmt).getExpr().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("check_type_failed")
		and target_3.getThen().(ReturnStmt).getExpr().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vop_152
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_3)
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vpdict_1_153, AddressOfExpr target_14, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpdict_1_153
		and target_4.getExpr().(AssignExpr).getRValue() instanceof ValueFieldAccess
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_4)
		and target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_5(Variable vmem_1_154, ExprCall target_9, ExprStmt target_15, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmem_1_154
		and target_5.getExpr().(AssignExpr).getRValue() instanceof ValueFieldAccess
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_5)
		and target_9.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Variable vdata_1_155, NotExpr target_16, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_1_155
		and target_6.getExpr().(AssignExpr).getRValue() instanceof ExprCall
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_6)
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation()))
}

predicate func_7(Variable vop_152, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="pdict"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_152
}

predicate func_8(Variable vpdict_1_153, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="pstruct"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdict_1_153
}

predicate func_9(Variable vmem_1_154, Variable vst_dsc_data_t, ExprCall target_9) {
		target_9.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_struct"
		and target_9.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_9.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmem_1_154
		and target_9.getArgument(0).(VariableAccess).getTarget()=vmem_1_154
		and target_9.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vst_dsc_data_t
		and target_9.getArgument(2).(StringLiteral).getValue()="DSC parser init"
}

predicate func_14(Variable vpdict_1_153, AddressOfExpr target_14) {
		target_14.getOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdict_1_153
}

predicate func_15(Variable vmem_1_154, Variable vdata_1_155, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dsc_data_ptr"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1_155
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dsc_init_with_alloc")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Ghostscript DSC parsing"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmem_1_154
}

predicate func_16(Variable vdata_1_155, NotExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vdata_1_155
}

from Function func, Variable vop_152, Variable vpdict_1_153, Variable vmem_1_154, Variable vdata_1_155, Variable vst_dsc_data_t, ValueFieldAccess target_7, ValueFieldAccess target_8, ExprCall target_9, AddressOfExpr target_14, ExprStmt target_15, NotExpr target_16
where
not func_3(vop_152, target_7, func)
and not func_4(vpdict_1_153, target_14, func)
and not func_5(vmem_1_154, target_9, target_15, func)
and not func_6(vdata_1_155, target_16, func)
and func_7(vop_152, target_7)
and func_8(vpdict_1_153, target_8)
and func_9(vmem_1_154, vst_dsc_data_t, target_9)
and func_14(vpdict_1_153, target_14)
and func_15(vmem_1_154, vdata_1_155, target_15)
and func_16(vdata_1_155, target_16)
and vop_152.getType().hasName("const os_ptr")
and vpdict_1_153.getType().hasName("dict *const")
and vmem_1_154.getType().hasName("gs_memory_t *const")
and vdata_1_155.getType().hasName("dsc_data_t *const")
and vst_dsc_data_t.getType().hasName("const gs_memory_struct_type_t")
and vop_152.(LocalVariable).getFunction() = func
and vpdict_1_153.(LocalVariable).getFunction() = func
and vmem_1_154.(LocalVariable).getFunction() = func
and vdata_1_155.(LocalVariable).getFunction() = func
and not vst_dsc_data_t.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
