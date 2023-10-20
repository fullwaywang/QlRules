/**
 * @name pcre2-03654e751e7f0700693526b67dfcadda6b42c9d0-get_recurse_data_length
 * @id cpp/pcre2/03654e751e7f0700693526b67dfcadda6b42c9d0/get-recurse-data-length
 * @description pcre2-03654e751e7f0700693526b67dfcadda6b42c9d0-get_recurse_data_length CVE-2022-1587
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vcommon_2320, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="recurse_bitset"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="recurse_bitset_size"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vcommon_2320) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand().(FunctionCall).getTarget().hasName("recurse_check_bit")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="capture_last_ptr"
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_2.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("int")
		and target_3.getRValue() instanceof ArrayExpr
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Parameter vcommon_2320) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("recurse_check_bit")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_5.getArgument(1).(VariableAccess).getType().hasName("int"))
}

predicate func_6(Parameter vcommon_2320) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("recurse_check_bit")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_6.getArgument(1) instanceof ArrayExpr)
}

predicate func_7(Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue() instanceof BitwiseOrExpr
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Parameter vcommon_2320) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("recurse_check_bit")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_8.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ovector_start"
		and target_8.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_8.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_8.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_8.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8")
}

predicate func_9(Parameter vcommon_2320, Variable vlength_2323) {
	exists(LogicalAndExpr target_9 |
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="optimized_cbracket"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getAnOperand().(FunctionCall).getTarget().hasName("recurse_check_bit")
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_9.getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="cbra_ptr"
		and target_9.getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_9.getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_9.getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlength_2323)
}

predicate func_14(Parameter vcommon_2320) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("recurse_check_bit")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_14.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="cbra_ptr"
		and target_14.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_14.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_14.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_14.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8")
}

predicate func_18(Parameter vcommon_2320, Variable vlength_2323) {
	exists(LogicalAndExpr target_18 |
		target_18.getAnOperand() instanceof LogicalOrExpr
		and target_18.getAnOperand().(FunctionCall).getTarget().hasName("recurse_check_bit")
		and target_18.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_18.getAnOperand().(FunctionCall).getArgument(1) instanceof ArrayExpr
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlength_2323)
}

predicate func_20(Function func) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_20.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
		and target_20.getEnclosingFunction() = func)
}

predicate func_21(Parameter vcommon_2320, Variable vlength_2323) {
	exists(LogicalAndExpr target_21 |
		target_21.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_21.getAnOperand().(FunctionCall).getTarget().hasName("recurse_check_bit")
		and target_21.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_21.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_21.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlength_2323)
}

predicate func_31(Parameter vcommon_2320, Variable vlength_2323) {
	exists(IfStmt target_31 |
		target_31.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_31.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_31.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("recurse_check_bit")
		and target_31.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_31.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_31.getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlength_2323)
}

predicate func_34(Parameter vcommon_2320) {
	exists(IfStmt target_34 |
		target_34.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("recurse_check_bit")
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_34.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_34.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_34.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt)
}

predicate func_44(Parameter vcommon_2320, Parameter vcc_2320, Variable vlength_2323, Variable vsize_2324) {
	exists(IfStmt target_44 |
		target_44.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_44.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_44.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("recurse_check_bit")
		and target_44.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_44.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_44.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlength_2323
		and target_44.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("get_class_iterator_size")
		and target_44.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcc_2320
		and target_44.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_2324)
}

predicate func_50(Parameter vcommon_2320) {
	exists(EqualityOperation target_50 |
		target_50.getAnOperand().(PointerFieldAccess).getTarget().getName()="capture_last_ptr"
		and target_50.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_50.getAnOperand().(Literal).getValue()="0"
		and target_50.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr)
}

predicate func_56(Parameter vcommon_2320, Parameter vcc_2320) {
	exists(BitwiseOrExpr target_56 |
		target_56.getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcc_2320
		and target_56.getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(AddExpr).getValue()="3"
		and target_56.getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_56.getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcc_2320
		and target_56.getRightOperand().(ArrayExpr).getArrayOffset().(AddExpr).getValue()="4"
		and target_56.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="optimized_cbracket"
		and target_56.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_57(Function func) {
	exists(AddExpr target_57 |
		target_57.getValue()="4"
		and target_57.getEnclosingFunction() = func)
}

predicate func_59(Variable vlength_2323, Variable valternative_2325) {
	exists(LogicalOrExpr target_59 |
		target_59.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=valternative_2325
		and target_59.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=valternative_2325
		and target_59.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlength_2323)
}

predicate func_73(Variable vcontrol_head_found_2331) {
	exists(ExprStmt target_73 |
		target_73.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcontrol_head_found_2331
		and target_73.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_73.getParent().(IfStmt).getCondition() instanceof NotExpr)
}

predicate func_76(Function func) {
	exists(DeclStmt target_76 |
		target_76.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_76)
}

predicate func_77(Variable vcapture_last_found_2330) {
	exists(AssignExpr target_77 |
		target_77.getLValue().(VariableAccess).getTarget()=vcapture_last_found_2330
		and target_77.getRValue().(Literal).getValue()="1")
}

predicate func_80(Variable vcontrol_head_found_2331) {
	exists(NotExpr target_80 |
		target_80.getOperand().(VariableAccess).getTarget()=vcontrol_head_found_2331
		and target_80.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_81(Variable vlength_2323, Variable vcapture_last_found_2330) {
	exists(VariableAccess target_81 |
		target_81.getTarget()=vcapture_last_found_2330
		and target_81.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlength_2323)
}

predicate func_82(Parameter vcommon_2320) {
	exists(PointerFieldAccess target_82 |
		target_82.getTarget().getName()="mark_ptr"
		and target_82.getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_83(Parameter vcommon_2320) {
	exists(PointerFieldAccess target_83 |
		target_83.getTarget().getName()="start"
		and target_83.getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_84(Parameter vcommon_2320) {
	exists(PointerFieldAccess target_84 |
		target_84.getTarget().getName()="capture_last_ptr"
		and target_84.getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_85(Parameter vcommon_2320) {
	exists(PointerFieldAccess target_85 |
		target_85.getTarget().getName()="optimized_cbracket"
		and target_85.getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_87(Parameter vcommon_2320) {
	exists(PointerFieldAccess target_87 |
		target_87.getTarget().getName()="utf"
		and target_87.getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_93(Parameter vcommon_2320) {
	exists(PointerFieldAccess target_93 |
		target_93.getTarget().getName()="control_head_ptr"
		and target_93.getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_94(Parameter vcommon_2320, Parameter vcc_2320) {
	exists(FunctionCall target_94 |
		target_94.getTarget().hasName("next_opcode")
		and target_94.getArgument(0).(VariableAccess).getTarget()=vcommon_2320
		and target_94.getArgument(1).(VariableAccess).getTarget()=vcc_2320)
}

predicate func_95(Parameter vcc_2320) {
	exists(AssignPointerAddExpr target_95 |
		target_95.getLValue().(VariableAccess).getTarget()=vcc_2320
		and target_95.getRValue().(AddExpr).getValue()="5")
}

predicate func_96(Parameter vcc_2320) {
	exists(AssignPointerAddExpr target_96 |
		target_96.getLValue().(VariableAccess).getTarget()=vcc_2320
		and target_96.getRValue().(Literal).getValue()="1")
}

predicate func_97(Parameter vcommon_2320, Parameter vcc_2320) {
	exists(PointerArithmeticOperation target_97 |
		target_97.getLeftOperand().(VariableAccess).getTarget()=vcc_2320
		and target_97.getRightOperand().(PointerFieldAccess).getTarget().getName()="start"
		and target_97.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320
		and target_97.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="private_data_ptrs"
		and target_97.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommon_2320)
}

predicate func_98(Parameter vcc_2320) {
	exists(ArrayExpr target_98 |
		target_98.getArrayBase().(VariableAccess).getTarget()=vcc_2320
		and target_98.getArrayOffset().(AddExpr).getValue()="2")
}

from Function func, Parameter vcommon_2320, Parameter vcc_2320, Variable vlength_2323, Variable vsize_2324, Variable valternative_2325, Variable vcapture_last_found_2330, Variable vcontrol_head_found_2331
where
not func_1(vcommon_2320, func)
and not func_2(vcommon_2320)
and not func_3(func)
and not func_5(vcommon_2320)
and not func_6(vcommon_2320)
and not func_7(func)
and not func_8(vcommon_2320)
and not func_9(vcommon_2320, vlength_2323)
and not func_14(vcommon_2320)
and not func_18(vcommon_2320, vlength_2323)
and not func_20(func)
and not func_21(vcommon_2320, vlength_2323)
and not func_31(vcommon_2320, vlength_2323)
and not func_34(vcommon_2320)
and not func_44(vcommon_2320, vcc_2320, vlength_2323, vsize_2324)
and func_50(vcommon_2320)
and func_56(vcommon_2320, vcc_2320)
and func_57(func)
and func_59(vlength_2323, valternative_2325)
and func_73(vcontrol_head_found_2331)
and func_76(func)
and func_77(vcapture_last_found_2330)
and func_80(vcontrol_head_found_2331)
and func_81(vlength_2323, vcapture_last_found_2330)
and vcommon_2320.getType().hasName("compiler_common *")
and func_82(vcommon_2320)
and func_83(vcommon_2320)
and func_84(vcommon_2320)
and func_85(vcommon_2320)
and func_87(vcommon_2320)
and func_93(vcommon_2320)
and func_94(vcommon_2320, vcc_2320)
and vcc_2320.getType().hasName("PCRE2_SPTR8")
and func_95(vcc_2320)
and func_96(vcc_2320)
and func_97(vcommon_2320, vcc_2320)
and func_98(vcc_2320)
and vlength_2323.getType().hasName("int")
and vsize_2324.getType().hasName("int")
and valternative_2325.getType().hasName("PCRE2_SPTR8")
and vcapture_last_found_2330.getType().hasName("BOOL")
and vcontrol_head_found_2331.getType().hasName("BOOL")
and vcommon_2320.getParentScope+() = func
and vcc_2320.getParentScope+() = func
and vlength_2323.getParentScope+() = func
and vsize_2324.getParentScope+() = func
and valternative_2325.getParentScope+() = func
and vcapture_last_found_2330.getParentScope+() = func
and vcontrol_head_found_2331.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
