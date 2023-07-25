/**
 * @name libtiff-c8d613ef497058fe653c467fc84c70a62a4a71b2-gtTileContig
 * @id cpp/libtiff/c8d613ef497058fe653c467fc84c70a62a4a71b2/gtTileContig
 * @description libtiff-c8d613ef497058fe653c467fc84c70a62a4a71b2-libtiff/tif_getimage.c-gtTileContig CVE-2020-35523
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vw_620, Variable vtif_622, Variable vtw_626, BitwiseAndExpr target_6, ExprStmt target_7, LogicalAndExpr target_8, AddressOfExpr target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtw_626
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_620
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_622
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_622
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="unsupported tile size (too wide)"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vtif_622, BitwiseAndExpr target_6, LogicalAndExpr target_8) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_622
		and target_1.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_1.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_622
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_1.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="unsupported tile size (too wide)"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_2(BitwiseAndExpr target_6, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_2.getEnclosingFunction() = func)
}

*/
predicate func_3(Parameter vw_620, Variable vtif_622, Variable vtw_626, BitwiseAndExpr target_6, ExprStmt target_7, ExprStmt target_5, ExprStmt target_10) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtw_626
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="2147483647"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_620
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_622
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_622
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="unsupported tile size (too wide)"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vy_624, BitwiseAndExpr target_6, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_624
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_5(Parameter vw_620, Variable vtw_626, Variable vtoskew_628, BitwiseAndExpr target_6, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtoskew_628
		and target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vtw_626
		and target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vw_620
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_6(BitwiseAndExpr target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getRightOperand().(Literal).getValue()="1"
}

predicate func_7(Parameter vw_620, Variable vtw_626, Variable vtoskew_628, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtoskew_628
		and target_7.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtw_626
		and target_7.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_620
}

predicate func_8(Variable vtif_622, LogicalAndExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadTileAndAllocBuffer")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_622
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFRGBAImage *")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="stoponerr"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFRGBAImage *")
}

predicate func_9(Variable vtw_626, AddressOfExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vtw_626
}

predicate func_10(Variable vtif_622, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_622
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="323"
		and target_10.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32")
}

from Function func, Parameter vw_620, Variable vtif_622, Variable vy_624, Variable vtw_626, Variable vtoskew_628, ExprStmt target_4, ExprStmt target_5, BitwiseAndExpr target_6, ExprStmt target_7, LogicalAndExpr target_8, AddressOfExpr target_9, ExprStmt target_10
where
not func_0(vw_620, vtif_622, vtw_626, target_6, target_7, target_8, target_9)
and not func_3(vw_620, vtif_622, vtw_626, target_6, target_7, target_5, target_10)
and func_4(vy_624, target_6, target_4)
and func_5(vw_620, vtw_626, vtoskew_628, target_6, target_5)
and func_6(target_6)
and func_7(vw_620, vtw_626, vtoskew_628, target_7)
and func_8(vtif_622, target_8)
and func_9(vtw_626, target_9)
and func_10(vtif_622, target_10)
and vw_620.getType().hasName("uint32")
and vtif_622.getType().hasName("TIFF *")
and vy_624.getType().hasName("uint32")
and vtw_626.getType().hasName("uint32")
and vtoskew_628.getType().hasName("int32")
and vw_620.getFunction() = func
and vtif_622.(LocalVariable).getFunction() = func
and vy_624.(LocalVariable).getFunction() = func
and vtw_626.(LocalVariable).getFunction() = func
and vtoskew_628.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
