/**
 * @name imagemagick-b3dd69b23e9338806891c708a0cc8a82c0d1872a-ExtractPostscript
 * @id cpp/imagemagick/b3dd69b23e9338806891c708a0cc8a82c0d1872a/ExtractPostscript
 * @description imagemagick-b3dd69b23e9338806891c708a0cc8a82c0d1872a-coders/wpg.c-ExtractPostscript CVE-2016-7527
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmagic_info_743, Variable vclone_info_749, EqualityOperation target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("strncpy")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="magick"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_info_749
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmagic_info_743
		and target_0.getArgument(2) instanceof Literal
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vclone_info_749, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="magick"
		and target_1.getQualifier().(VariableAccess).getTarget()=vclone_info_749
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_2(Variable vmagic_info_743, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="name"
		and target_2.getQualifier().(VariableAccess).getTarget()=vmagic_info_743
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Variable vmagic_info_743, Variable vclone_info_749, FunctionCall target_4) {
		target_4.getTarget().hasName("CopyMagickMemory")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="magick"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_info_749
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmagic_info_743
		and target_4.getArgument(2) instanceof Literal
}

predicate func_5(Variable vmagic_info_743, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmagic_info_743
		and target_5.getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vclone_info_749, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_info_749
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_7(Variable vclone_info_749, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="filename"
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_info_749
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
}

from Function func, Variable vmagic_info_743, Variable vclone_info_749, PointerFieldAccess target_1, PointerFieldAccess target_2, FunctionCall target_4, EqualityOperation target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vmagic_info_743, vclone_info_749, target_5, target_6, target_7)
and func_1(vclone_info_749, target_1)
and func_2(vmagic_info_743, target_2)
and func_4(vmagic_info_743, vclone_info_749, target_4)
and func_5(vmagic_info_743, target_5)
and func_6(vclone_info_749, target_6)
and func_7(vclone_info_749, target_7)
and vmagic_info_743.getType().hasName("const MagicInfo *")
and vclone_info_749.getType().hasName("ImageInfo *")
and vmagic_info_743.getParentScope+() = func
and vclone_info_749.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
