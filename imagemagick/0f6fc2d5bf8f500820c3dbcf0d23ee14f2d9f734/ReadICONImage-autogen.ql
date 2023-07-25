/**
 * @name imagemagick-0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734-ReadICONImage
 * @id cpp/imagemagick/0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734/ReadICONImage
 * @description imagemagick-0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734-coders/icon.c-ReadICONImage CVE-2015-8895
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_info_240, Parameter vexception_241, Variable vimage_250, Variable v__func__, Variable vlength_348, LogicalOrExpr target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, AddExpr target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ComplementExpr).getOperand().(VariableAccess).getTarget()=vlength_348
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_241
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_240
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_250
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_250
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_250
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr() instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ComplementExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ComplementExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(LogicalOrExpr target_4, Function func) {
	exists(EmptyStmt target_1 |
		target_1.toString() = ";"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(LogicalOrExpr target_4, Function func) {
	exists(EmptyStmt target_2 |
		target_2.toString() = ";"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(LogicalOrExpr target_4, Function func, EmptyStmt target_3) {
		target_3.toString() = ";"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(LogicalOrExpr target_4) {
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="planes"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="18505"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="bits_per_pixel"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="21060"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="1196314761"
}

predicate func_5(Parameter vimage_info_240, Parameter vexception_241, Variable v__func__, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_241
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="ImproperImageHeader"
		and target_5.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_5.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_5.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_240
}

predicate func_6(Parameter vimage_info_240, Parameter vexception_241, Variable v__func__, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_241
		and target_6.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_6.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_6.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_6.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_240
}

predicate func_7(Parameter vexception_241, Variable vimage_250, Variable v__func__, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_241
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="UnexpectedEndOfFile"
		and target_7.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="'%s': %s"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_250
}

predicate func_8(Variable vlength_348, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_348
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="size"
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="directory"
}

predicate func_9(Variable vlength_348, AddExpr target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vlength_348
		and target_9.getAnOperand().(Literal).getValue()="16"
}

from Function func, Parameter vimage_info_240, Parameter vexception_241, Variable vimage_250, Variable v__func__, Variable vlength_348, EmptyStmt target_3, LogicalOrExpr target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, AddExpr target_9
where
not func_0(vimage_info_240, vexception_241, vimage_250, v__func__, vlength_348, target_4, target_5, target_6, target_7, target_8, target_9)
and not func_1(target_4, func)
and not func_2(target_4, func)
and func_3(target_4, func, target_3)
and func_4(target_4)
and func_5(vimage_info_240, vexception_241, v__func__, target_5)
and func_6(vimage_info_240, vexception_241, v__func__, target_6)
and func_7(vexception_241, vimage_250, v__func__, target_7)
and func_8(vlength_348, target_8)
and func_9(vlength_348, target_9)
and vimage_info_240.getType().hasName("const ImageInfo *")
and vexception_241.getType().hasName("ExceptionInfo *")
and vimage_250.getType().hasName("Image *")
and v__func__.getType() instanceof ArrayType
and vlength_348.getType().hasName("size_t")
and vimage_info_240.getParentScope+() = func
and vexception_241.getParentScope+() = func
and vimage_250.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vlength_348.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
