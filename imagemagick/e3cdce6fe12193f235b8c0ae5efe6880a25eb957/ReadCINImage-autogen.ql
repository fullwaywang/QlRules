/**
 * @name imagemagick-e3cdce6fe12193f235b8c0ae5efe6880a25eb957-ReadCINImage
 * @id cpp/imagemagick/e3cdce6fe12193f235b8c0ae5efe6880a25eb957/ReadCINImage
 * @description imagemagick-e3cdce6fe12193f235b8c0ae5efe6880a25eb957-coders/cin.c-ReadCINImage CVE-2019-11470
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_379, Variable vimage_394, Parameter vimage_info_379, Variable v__func__, ExprStmt target_2, ExprStmt target_3, ReturnStmt target_4, EqualityOperation target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_394
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_394
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("GetBlobSize")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_394
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_379
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="InsufficientImageDataInFile"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="InsufficientImageDataInFile"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_379
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_394
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_394
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_394
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(139)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(139).getFollowingStmt()=target_0)
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vexception_379, Variable vimage_394, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("SetImageProfile")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_394
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dpx:user.data"
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexception_379
}

predicate func_3(Parameter vexception_379, Parameter vimage_info_379, Variable v__func__, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_379
		and target_3.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_3.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_3.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_379
}

predicate func_4(Variable vimage_394, ReturnStmt target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vimage_394
}

predicate func_5(Parameter vimage_info_379, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="ping"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_379
}

predicate func_6(Parameter vexception_379, Parameter vimage_info_379, Variable v__func__, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_379
		and target_6.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_6.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_6.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_379
}

from Function func, Parameter vexception_379, Variable vimage_394, Parameter vimage_info_379, Variable v__func__, ExprStmt target_2, ExprStmt target_3, ReturnStmt target_4, EqualityOperation target_5, ExprStmt target_6
where
not func_0(vexception_379, vimage_394, vimage_info_379, v__func__, target_2, target_3, target_4, target_5, target_6, func)
and func_2(vexception_379, vimage_394, target_2)
and func_3(vexception_379, vimage_info_379, v__func__, target_3)
and func_4(vimage_394, target_4)
and func_5(vimage_info_379, target_5)
and func_6(vexception_379, vimage_info_379, v__func__, target_6)
and vexception_379.getType().hasName("ExceptionInfo *")
and vimage_394.getType().hasName("Image *")
and vimage_info_379.getType().hasName("const ImageInfo *")
and v__func__.getType() instanceof ArrayType
and vexception_379.getParentScope+() = func
and vimage_394.getParentScope+() = func
and vimage_info_379.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
