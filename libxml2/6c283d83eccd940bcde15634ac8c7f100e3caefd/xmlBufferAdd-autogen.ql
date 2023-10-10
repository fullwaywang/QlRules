/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferAdd
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufferAdd
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-tree.c-xmlBufferAdd CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_7577, Parameter vlen_7577, EqualityOperation target_5, EqualityOperation target_6, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_7577
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_1(Parameter vbuf_7577, Parameter vlen_7577, BlockStmt target_7, RelationalOperation target_4, ExprStmt target_8) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vlen_7577
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vbuf_7577, Parameter vlen_7577, RelationalOperation target_4, NotExpr target_9, MulExpr target_10) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_7577
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getValue()="4294967295"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vbuf_7577, Variable vneedSize_7578, BlockStmt target_7, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="size"
		and target_3.getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_3.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vneedSize_7578
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Parameter vbuf_7577, Variable vneedSize_7578, BlockStmt target_7, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vneedSize_7578
		and target_4.getLesserOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_4.getParent().(IfStmt).getThen()=target_7
}

predicate func_5(Parameter vbuf_7577, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
}

predicate func_6(Parameter vlen_7577, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vlen_7577
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Parameter vbuf_7577, Variable vneedSize_7578, BlockStmt target_7) {
		target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlBufferResize")
		and target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_7577
		and target_7.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vneedSize_7578
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlTreeErrMemory")
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="growing buffer"
}

predicate func_8(Parameter vbuf_7577, Parameter vlen_7577, Variable vneedSize_7578, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vneedSize_7578
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_7577
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof Literal
}

predicate func_9(Parameter vbuf_7577, Variable vneedSize_7578, NotExpr target_9) {
		target_9.getOperand().(FunctionCall).getTarget().hasName("xmlBufferResize")
		and target_9.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_7577
		and target_9.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vneedSize_7578
}

predicate func_10(Parameter vlen_7577, MulExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vlen_7577
		and target_10.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

from Function func, Parameter vbuf_7577, Parameter vlen_7577, Variable vneedSize_7578, Literal target_0, PointerFieldAccess target_3, RelationalOperation target_4, EqualityOperation target_5, EqualityOperation target_6, BlockStmt target_7, ExprStmt target_8, NotExpr target_9, MulExpr target_10
where
func_0(vbuf_7577, vlen_7577, target_5, target_6, target_0)
and not func_1(vbuf_7577, vlen_7577, target_7, target_4, target_8)
and not func_2(vbuf_7577, vlen_7577, target_4, target_9, target_10)
and func_3(vbuf_7577, vneedSize_7578, target_7, target_3)
and func_4(vbuf_7577, vneedSize_7578, target_7, target_4)
and func_5(vbuf_7577, target_5)
and func_6(vlen_7577, target_6)
and func_7(vbuf_7577, vneedSize_7578, target_7)
and func_8(vbuf_7577, vlen_7577, vneedSize_7578, target_8)
and func_9(vbuf_7577, vneedSize_7578, target_9)
and func_10(vlen_7577, target_10)
and vbuf_7577.getType().hasName("xmlBufferPtr")
and vlen_7577.getType().hasName("int")
and vneedSize_7578.getType().hasName("unsigned int")
and vbuf_7577.getFunction() = func
and vlen_7577.getFunction() = func
and vneedSize_7578.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
