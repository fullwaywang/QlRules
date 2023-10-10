/**
 * @name pcre2-03654e751e7f0700693526b67dfcadda6b42c9d0-jit_compile
 * @id cpp/pcre2/03654e751e7f0700693526b67dfcadda6b42c9d0/jit-compile
 * @description pcre2-03654e751e7f0700693526b67dfcadda6b42c9d0-jit_compile CVE-2022-1587
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SizeofTypeOperator target_0 |
		target_0.getType() instanceof LongType
		and target_0.getValue()="536"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vcommon_13627, Variable vprivate_data_size_13630) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="recurse_bitset_size"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vprivate_data_size_13630
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_2(Variable vcommon_13627, Variable vallocator_data_13629) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="recurse_bitset"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pcre2_jit_malloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="recurse_bitset_size"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vallocator_data_13629
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_3(Function func) {
	exists(EmptyStmt target_3 |
		target_3.toString() = ";"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vcommon_13627, Variable vallocator_data_13629) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="recurse_bitset"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="currententry"
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof FunctionCall
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pcre2_jit_free")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="recurse_bitset"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vallocator_data_13629
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_9(Variable vcommon_13627) {
	exists(IfStmt target_9 |
		target_9.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="currententry"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_9.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(5) instanceof ReturnStmt
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_13(Variable vcommon_13627) {
	exists(EqualityOperation target_13 |
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="currententry"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_13.getAnOperand().(Literal).getValue()="0")
}

predicate func_14(Variable vcommon_13627) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("compile_recurse")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_13627)
}

predicate func_16(Variable vcompiler_13624) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("sljit_free_compiler")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompiler_13624
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("sljit_get_compiler_error")
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompiler_13624
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_17(Variable vcompiler_13624, Variable vcommon_13627, Variable vallocator_data_13629) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(FunctionCall).getTarget().hasName("pcre2_jit_free")
		and target_17.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="optimized_cbracket"
		and target_17.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_17.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vallocator_data_13629
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("sljit_get_compiler_error")
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompiler_13624
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_18(Variable vcompiler_13624, Variable vcommon_13627, Variable vallocator_data_13629) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(FunctionCall).getTarget().hasName("pcre2_jit_free")
		and target_18.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="private_data_ptrs"
		and target_18.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_18.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vallocator_data_13629
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("sljit_get_compiler_error")
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompiler_13624
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_19(Variable vcompiler_13624, Variable vcommon_13627, Variable vallocator_data_13629) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(FunctionCall).getTarget().hasName("_pcre2_jit_free_rodata_8")
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="read_only_data_head"
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_19.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vallocator_data_13629
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("sljit_get_compiler_error")
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompiler_13624
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_20(Variable vcompiler_13624) {
	exists(ReturnStmt target_20 |
		target_20.getExpr().(UnaryMinusExpr).getValue()="-48"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("sljit_get_compiler_error")
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompiler_13624
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_21(Variable vcommon_13627) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(FunctionCall).getTarget().hasName("flush_stubs")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_13627)
}

predicate func_22(Variable vcommon_13627) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="currententry"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="currententry"
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627)
}

predicate func_24(Function func) {
	exists(WhileStmt target_24 |
		target_24.getCondition() instanceof EqualityOperation
		and target_24.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_24.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof FunctionCall
		and target_24.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_24.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_24.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_24.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_24.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4) instanceof ReturnStmt
		and target_24.getStmt().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_24.getStmt().(BlockStmt).getStmt(3) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_24)
}

predicate func_25(Variable vcommon_13627) {
	exists(PointerFieldAccess target_25 |
		target_25.getTarget().getName()="currententry"
		and target_25.getQualifier().(VariableAccess).getTarget()=vcommon_13627)
}

predicate func_26(Variable vcommon_13627) {
	exists(FunctionCall target_26 |
		target_26.getTarget().hasName("compile_recurse")
		and target_26.getArgument(0).(VariableAccess).getTarget()=vcommon_13627)
}

predicate func_27(Variable vcommon_13627, Variable vallocator_data_13629) {
	exists(FunctionCall target_27 |
		target_27.getTarget().hasName("_pcre2_jit_free_rodata_8")
		and target_27.getArgument(0).(PointerFieldAccess).getTarget().getName()="read_only_data_head"
		and target_27.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_13627
		and target_27.getArgument(1).(VariableAccess).getTarget()=vallocator_data_13629)
}

predicate func_28(Variable vcompiler_13624, Variable vprivate_data_size_13630) {
	exists(FunctionCall target_28 |
		target_28.getTarget().hasName("sljit_emit_enter")
		and target_28.getArgument(0).(VariableAccess).getTarget()=vcompiler_13624
		and target_28.getArgument(1).(Literal).getValue()="0"
		and target_28.getArgument(2).(BitwiseOrExpr).getValue()="17"
		and target_28.getArgument(3).(Literal).getValue()="5"
		and target_28.getArgument(4).(Literal).getValue()="5"
		and target_28.getArgument(5).(Literal).getValue()="0"
		and target_28.getArgument(6).(Literal).getValue()="0"
		and target_28.getArgument(7).(VariableAccess).getTarget()=vprivate_data_size_13630)
}

from Function func, Variable vcompiler_13624, Variable vcommon_13627, Variable vallocator_data_13629, Variable vprivate_data_size_13630
where
func_0(func)
and not func_1(vcommon_13627, vprivate_data_size_13630)
and not func_2(vcommon_13627, vallocator_data_13629)
and not func_3(func)
and not func_4(vcommon_13627, vallocator_data_13629)
and not func_9(vcommon_13627)
and func_13(vcommon_13627)
and func_14(vcommon_13627)
and func_16(vcompiler_13624)
and func_17(vcompiler_13624, vcommon_13627, vallocator_data_13629)
and func_18(vcompiler_13624, vcommon_13627, vallocator_data_13629)
and func_19(vcompiler_13624, vcommon_13627, vallocator_data_13629)
and func_20(vcompiler_13624)
and func_21(vcommon_13627)
and func_22(vcommon_13627)
and func_24(func)
and vcompiler_13624.getType().hasName("sljit_compiler *")
and vcommon_13627.getType().hasName("compiler_common *")
and func_25(vcommon_13627)
and func_26(vcommon_13627)
and vallocator_data_13629.getType().hasName("void *")
and func_27(vcommon_13627, vallocator_data_13629)
and vprivate_data_size_13630.getType().hasName("int")
and func_28(vcompiler_13624, vprivate_data_size_13630)
and vcompiler_13624.getParentScope+() = func
and vcommon_13627.getParentScope+() = func
and vallocator_data_13629.getParentScope+() = func
and vprivate_data_size_13630.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
