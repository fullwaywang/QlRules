/**
 * @name libtiff-ec8ef90c1f573c9eb1f17d6a056aa0015f184acf-loadImage
 * @id cpp/libtiff/ec8ef90c1f573c9eb1f17d6a056aa0015f184acf/loadImage
 * @description libtiff-ec8ef90c1f573c9eb1f17d6a056aa0015f184acf-tools/tiffcrop.c-loadImage CVE-2023-26965
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Unable to allocate/reallocate read buffer"
		and not target_0.getValue()="Required read buffer size too large"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="Unable to allocate/reallocate read buffer"
		and not target_1.getValue()="Unable to allocate read buffer"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vread_buff_6773, FunctionCall target_2) {
		target_2.getTarget().hasName("free")
		and not target_2.getTarget().hasName("_TIFFfree")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vread_buff_6773
}

predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()="Unable to allocate/reallocate read buffer"
		and not target_3.getValue()="Unable to allocate read buffer"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vbuffsize_6769, Variable vread_buff_6773, NotExpr target_8, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_6773
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_5(Variable vread_buff_6773, BlockStmt target_15, VariableAccess target_5) {
		target_5.getTarget()=vread_buff_6773
		and target_5.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_15
}

predicate func_6(Function func, DeclStmt target_6) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Function func, DeclStmt target_7) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vread_buff_6773, BlockStmt target_15, ExprStmt target_16, NotExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vread_buff_6773
		and target_8.getParent().(IfStmt).getThen()=target_15
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getOperand().(VariableAccess).getLocation())
}

predicate func_9(Variable vbuffsize_6769, Variable vread_buff_6773, Variable vnew_buff_6774, Variable vprev_readsize_6776, NotExpr target_8, IfStmt target_9) {
		target_9.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vprev_readsize_6776
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967292"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_buff_6774
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vread_buff_6773
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_9.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vnew_buff_6774
		and target_9.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_9.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_6773
		and target_9.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_9.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_6773
		and target_9.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnew_buff_6774
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

/*predicate func_10(Variable vbuffsize_6769, RelationalOperation target_17, AddExpr target_18, IfStmt target_10) {
		target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967292"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_10.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_18.getAnOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_11(Variable vbuffsize_6769, Variable vread_buff_6773, Variable vnew_buff_6774, RelationalOperation target_17, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_buff_6774
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vread_buff_6773
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
/*predicate func_12(Variable vbuffsize_6769, Variable vread_buff_6773, Variable vnew_buff_6774, RelationalOperation target_17, IfStmt target_12) {
		target_12.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vnew_buff_6774
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_6773
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_6773
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnew_buff_6774
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
/*predicate func_13(Variable vbuffsize_6769, Variable vread_buff_6773, NotExpr target_19, AddExpr target_18, ExprStmt target_20, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_6773
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_18.getAnOperand().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
}

*/
predicate func_14(Variable vbuffsize_6769, Variable vprev_readsize_6776, Function func, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprev_readsize_6776
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuffsize_6769
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Variable vbuffsize_6769, BlockStmt target_15) {
		target_15.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_15.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967292"
		and target_15.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_15.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_15.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_15.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_16(Variable vread_buff_6773, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_buff_6773
		and target_16.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char **")
}

predicate func_17(Variable vbuffsize_6769, Variable vprev_readsize_6776, RelationalOperation target_17) {
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vprev_readsize_6776
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vbuffsize_6769
}

predicate func_18(Variable vbuffsize_6769, AddExpr target_18) {
		target_18.getAnOperand().(VariableAccess).getTarget()=vbuffsize_6769
		and target_18.getAnOperand() instanceof Literal
}

predicate func_19(Variable vnew_buff_6774, NotExpr target_19) {
		target_19.getOperand().(VariableAccess).getTarget()=vnew_buff_6774
}

predicate func_20(Variable vbuffsize_6769, Variable vread_buff_6773, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vread_buff_6773
		and target_20.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vbuffsize_6769
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vbuffsize_6769, Variable vread_buff_6773, Variable vnew_buff_6774, Variable vprev_readsize_6776, StringLiteral target_0, StringLiteral target_1, FunctionCall target_2, StringLiteral target_3, ExprStmt target_4, VariableAccess target_5, DeclStmt target_6, DeclStmt target_7, NotExpr target_8, IfStmt target_9, ExprStmt target_14, BlockStmt target_15, ExprStmt target_16, RelationalOperation target_17, AddExpr target_18, NotExpr target_19, ExprStmt target_20
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vread_buff_6773, target_2)
and func_3(func, target_3)
and func_4(vbuffsize_6769, vread_buff_6773, target_8, target_4)
and func_5(vread_buff_6773, target_15, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(vread_buff_6773, target_15, target_16, target_8)
and func_9(vbuffsize_6769, vread_buff_6773, vnew_buff_6774, vprev_readsize_6776, target_8, target_9)
and func_14(vbuffsize_6769, vprev_readsize_6776, func, target_14)
and func_15(vbuffsize_6769, target_15)
and func_16(vread_buff_6773, target_16)
and func_17(vbuffsize_6769, vprev_readsize_6776, target_17)
and func_18(vbuffsize_6769, target_18)
and func_19(vnew_buff_6774, target_19)
and func_20(vbuffsize_6769, vread_buff_6773, target_20)
and vbuffsize_6769.getType().hasName("tmsize_t")
and vread_buff_6773.getType().hasName("unsigned char *")
and vnew_buff_6774.getType().hasName("unsigned char *")
and vprev_readsize_6776.getType().hasName("tmsize_t")
and vbuffsize_6769.(LocalVariable).getFunction() = func
and vread_buff_6773.(LocalVariable).getFunction() = func
and vnew_buff_6774.(LocalVariable).getFunction() = func
and vprev_readsize_6776.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()