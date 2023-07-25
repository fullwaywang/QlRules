/**
 * @name imagemagick-7fd419441bc7103398e313558171d342c6315f44-ReadMPCImage
 * @id cpp/imagemagick/7fd419441bc7103398e313558171d342c6315f44/ReadMPCImage
 * @description imagemagick-7fd419441bc7103398e313558171d342c6315f44-coders/mpc.c-ReadMPCImage CVE-2017-9499
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_145, Variable vimage_160, Parameter vimage_info_145, Variable v__func__, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="number_meta_channels"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_160
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_145
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_145
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_160
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_160
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_160
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("LocaleCompare")
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="number-meta-channels"
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vexception_145, Variable vimage_160, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("SetImageProperty")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_160
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexception_145
}

predicate func_5(Parameter vexception_145, Variable vimage_160, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("SetImageProperty")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_160
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexception_145
}

predicate func_6(Variable vimage_160, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="number_meta_channels"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_160
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("StringToUnsignedLong")
}

predicate func_7(Parameter vexception_145, Parameter vimage_info_145, Variable v__func__, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_145
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_7.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_145
}

predicate func_8(Parameter vexception_145, Parameter vimage_info_145, Variable v__func__, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_145
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_8.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_145
}

from Function func, Parameter vexception_145, Variable vimage_160, Parameter vimage_info_145, Variable v__func__, EmptyStmt target_2, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vexception_145, vimage_160, vimage_info_145, v__func__, target_3, target_4, target_5, target_6, target_7, target_8)
and func_2(func, target_2)
and func_3(target_3)
and func_4(vexception_145, vimage_160, target_4)
and func_5(vexception_145, vimage_160, target_5)
and func_6(vimage_160, target_6)
and func_7(vexception_145, vimage_info_145, v__func__, target_7)
and func_8(vexception_145, vimage_info_145, v__func__, target_8)
and vexception_145.getType().hasName("ExceptionInfo *")
and vimage_160.getType().hasName("Image *")
and vimage_info_145.getType().hasName("const ImageInfo *")
and v__func__.getType() instanceof ArrayType
and vexception_145.getParentScope+() = func
and vimage_160.getParentScope+() = func
and vimage_info_145.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
