/**
 * @name imagemagick-aecd0ada163a4d6c769cec178955d5f3e9316f2f-OpenPixelCache
 * @id cpp/imagemagick/aecd0ada163a4d6c769cec178955d5f3e9316f2f/OpenPixelCache
 * @description imagemagick-aecd0ada163a4d6c769cec178955d5f3e9316f2f-MagickCore/cache.c-OpenPixelCache CVE-2016-5688
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcache_info_3326, LogicalOrExpr target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcache_info_3326, EqualityOperation target_8, ExprStmt target_9, AddExpr target_10) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcache_info_3326, EqualityOperation target_11, AddExpr target_10, ExprStmt target_12) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vcache_info_3326, Variable vstatus_3337, EqualityOperation target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ReturnStmt target_17) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_3337
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(8)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_14.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_17.getExpr().(VariableAccess).getLocation()))
}

predicate func_4(Variable vcache_info_3326, Variable vstatus_3337, ExprStmt target_18, ExprStmt target_19, ReturnStmt target_20, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_3337
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and (func.getEntryPoint().(BlockStmt).getStmt(54)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(54).getFollowingStmt()=target_4)
		and target_18.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_20.getExpr().(VariableAccess).getLocation()))
}

predicate func_5(Variable vcache_info_3326, Variable vstatus_3337, LogicalOrExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_3337
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_6(Variable vcache_info_3326, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("RelinquishMagickResource")
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="length"
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_7(Variable vcache_info_3326, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("ClosePixelCacheOnDisk")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_8(Variable vcache_info_3326, EqualityOperation target_8) {
		target_8.getAnOperand().(FunctionCall).getTarget().hasName("OpenPixelCacheOnDisk")
		and target_8.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_9(Variable vcache_info_3326, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("RelinquishMagickResource")
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="length"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_10(Variable vcache_info_3326, AddExpr target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_11(Variable vstatus_3337, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vstatus_3337
}

predicate func_12(Variable vcache_info_3326, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="number_channels"
		and target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="metacontent_extent"
		and target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_13(Variable vcache_info_3326, EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="pixels"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vcache_info_3326, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_14.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_14.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="open %s (%s[%d], %s, %.20gx%.20gx%.20g %s)"
		and target_14.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="filename"
		and target_14.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_14.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="cache_filename"
		and target_14.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_14.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="file"
		and target_14.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_14.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="columns"
		and target_14.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_14.getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="rows"
		and target_14.getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_14.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="number_channels"
		and target_14.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_15(Variable vcache_info_3326, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("RelinquishMagickResource")
		and target_15.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="length"
		and target_15.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_16(Variable vcache_info_3326, Variable vstatus_3337, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_3337
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ClonePixelCacheRepository")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_17(Variable vstatus_3337, ReturnStmt target_17) {
		target_17.getExpr().(VariableAccess).getTarget()=vstatus_3337
}

predicate func_18(Variable vcache_info_3326, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_18.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_18.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="open %s (%s[%d], %s, %.20gx%.20gx%.20g %s)"
		and target_18.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="filename"
		and target_18.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_18.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="cache_filename"
		and target_18.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_18.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="file"
		and target_18.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_18.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="columns"
		and target_18.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_18.getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="rows"
		and target_18.getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
		and target_18.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="number_channels"
		and target_18.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_19(Variable vcache_info_3326, Variable vstatus_3337, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_3337
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ClonePixelCacheRepository")
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcache_info_3326
}

predicate func_20(Variable vstatus_3337, ReturnStmt target_20) {
		target_20.getExpr().(VariableAccess).getTarget()=vstatus_3337
}

from Function func, Variable vcache_info_3326, Variable vstatus_3337, LogicalOrExpr target_5, ExprStmt target_6, ExprStmt target_7, EqualityOperation target_8, ExprStmt target_9, AddExpr target_10, EqualityOperation target_11, ExprStmt target_12, EqualityOperation target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ReturnStmt target_17, ExprStmt target_18, ExprStmt target_19, ReturnStmt target_20
where
not func_0(vcache_info_3326, target_5, target_6, target_7)
and not func_1(vcache_info_3326, target_8, target_9, target_10)
and not func_2(vcache_info_3326, target_11, target_10, target_12)
and not func_3(vcache_info_3326, vstatus_3337, target_13, target_14, target_15, target_16, target_17)
and not func_4(vcache_info_3326, vstatus_3337, target_18, target_19, target_20, func)
and func_5(vcache_info_3326, vstatus_3337, target_5)
and func_6(vcache_info_3326, target_6)
and func_7(vcache_info_3326, target_7)
and func_8(vcache_info_3326, target_8)
and func_9(vcache_info_3326, target_9)
and func_10(vcache_info_3326, target_10)
and func_11(vstatus_3337, target_11)
and func_12(vcache_info_3326, target_12)
and func_13(vcache_info_3326, target_13)
and func_14(vcache_info_3326, target_14)
and func_15(vcache_info_3326, target_15)
and func_16(vcache_info_3326, vstatus_3337, target_16)
and func_17(vstatus_3337, target_17)
and func_18(vcache_info_3326, target_18)
and func_19(vcache_info_3326, vstatus_3337, target_19)
and func_20(vstatus_3337, target_20)
and vcache_info_3326.getType().hasName("CacheInfo *__restrict__")
and vstatus_3337.getType().hasName("MagickBooleanType")
and vcache_info_3326.getParentScope+() = func
and vstatus_3337.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
