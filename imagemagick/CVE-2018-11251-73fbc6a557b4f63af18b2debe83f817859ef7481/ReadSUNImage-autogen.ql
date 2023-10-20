/**
 * @name imagemagick-73fbc6a557b4f63af18b2debe83f817859ef7481-ReadSUNImage
 * @id cpp/imagemagick/73fbc6a557b4f63af18b2debe83f817859ef7481/ReadSUNImage
 * @description imagemagick-73fbc6a557b4f63af18b2debe83f817859ef7481-coders/sun.c-ReadSUNImage CVE-2018-11251
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_218, Variable vimage_241, Parameter vimage_info_218, Variable v__func__, RelationalOperation target_3, ExprStmt target_4, EqualityOperation target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colors"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_241
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_218
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_218
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_241
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_241
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_241
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(ValueFieldAccess).getTarget().getName()="depth"
		and target_3.getGreaterOperand().(Literal).getValue()="24"
}

predicate func_4(Parameter vexception_218, Parameter vimage_info_218, Variable v__func__, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_218
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ColormapTypeNotSupported"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ColormapTypeNotSupported"
		and target_4.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_218
}

predicate func_5(Parameter vexception_218, Variable vimage_241, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("AcquireImageColormap")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_241
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="colors"
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_241
		and target_5.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexception_218
}

predicate func_6(Variable vimage_241, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colors"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_241
		and target_6.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="maplength"
		and target_6.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="3"
}

predicate func_7(Parameter vexception_218, Parameter vimage_info_218, Variable v__func__, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_218
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_7.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_218
}

from Function func, Parameter vexception_218, Variable vimage_241, Parameter vimage_info_218, Variable v__func__, EmptyStmt target_2, RelationalOperation target_3, ExprStmt target_4, EqualityOperation target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vexception_218, vimage_241, vimage_info_218, v__func__, target_3, target_4, target_5, target_6, target_7)
and func_2(func, target_2)
and func_3(target_3)
and func_4(vexception_218, vimage_info_218, v__func__, target_4)
and func_5(vexception_218, vimage_241, target_5)
and func_6(vimage_241, target_6)
and func_7(vexception_218, vimage_info_218, v__func__, target_7)
and vexception_218.getType().hasName("ExceptionInfo *")
and vimage_241.getType().hasName("Image *")
and vimage_info_218.getType().hasName("const ImageInfo *")
and v__func__.getType() instanceof ArrayType
and vexception_218.getParentScope+() = func
and vimage_241.getParentScope+() = func
and vimage_info_218.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
