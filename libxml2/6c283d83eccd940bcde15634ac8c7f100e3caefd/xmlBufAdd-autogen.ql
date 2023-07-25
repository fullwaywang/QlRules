/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufAdd
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufAdd
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-buf.c-xmlBufAdd CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_855, Parameter vlen_855, EqualityOperation target_8, EqualityOperation target_9, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_855
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(Parameter vbuf_855, Parameter vlen_855, BlockStmt target_10, RelationalOperation target_7) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vlen_855
		and target_2.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_2.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_2.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_2.getParent().(IfStmt).getThen()=target_10
		and target_2.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vbuf_855, Parameter vlen_855, RelationalOperation target_7, EqualityOperation target_12, MulExpr target_13) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_855
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_3.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vbuf_855, Parameter vlen_855, Variable vneedSize_856, EqualityOperation target_8, EqualityOperation target_9) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vneedSize_856
		and target_4.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_4.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_4.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_855
		and target_4.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vbuf_855, Variable vneedSize_856, BlockStmt target_10, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="size"
		and target_5.getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_5.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vneedSize_856
		and target_5.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_10
}

predicate func_6(Parameter vbuf_855, Parameter vlen_855, Variable vneedSize_856, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vneedSize_856
		and target_6.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_6.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_6.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_855
		and target_6.getRValue().(AddExpr).getAnOperand() instanceof Literal
}

predicate func_7(Parameter vbuf_855, Variable vneedSize_856, BlockStmt target_10, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vneedSize_856
		and target_7.getLesserOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_7.getParent().(IfStmt).getThen()=target_10
}

predicate func_8(Parameter vbuf_855, EqualityOperation target_8) {
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
}

predicate func_9(Parameter vlen_855, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vlen_855
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Parameter vbuf_855, Variable vneedSize_856, BlockStmt target_10) {
		target_10.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_10.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
		and target_10.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vneedSize_856
		and target_10.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_10.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlBufMemoryError")
}

predicate func_12(Parameter vbuf_855, EqualityOperation target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_855
}

predicate func_13(Parameter vlen_855, MulExpr target_13) {
		target_13.getLeftOperand().(VariableAccess).getTarget()=vlen_855
		and target_13.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_13.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

from Function func, Parameter vbuf_855, Parameter vlen_855, Variable vneedSize_856, Literal target_0, PointerFieldAccess target_5, AssignExpr target_6, RelationalOperation target_7, EqualityOperation target_8, EqualityOperation target_9, BlockStmt target_10, EqualityOperation target_12, MulExpr target_13
where
func_0(vbuf_855, vlen_855, target_8, target_9, target_0)
and not func_2(vbuf_855, vlen_855, target_10, target_7)
and not func_3(vbuf_855, vlen_855, target_7, target_12, target_13)
and not func_4(vbuf_855, vlen_855, vneedSize_856, target_8, target_9)
and func_5(vbuf_855, vneedSize_856, target_10, target_5)
and func_6(vbuf_855, vlen_855, vneedSize_856, target_6)
and func_7(vbuf_855, vneedSize_856, target_10, target_7)
and func_8(vbuf_855, target_8)
and func_9(vlen_855, target_9)
and func_10(vbuf_855, vneedSize_856, target_10)
and func_12(vbuf_855, target_12)
and func_13(vlen_855, target_13)
and vbuf_855.getType().hasName("xmlBufPtr")
and vlen_855.getType().hasName("int")
and vneedSize_856.getType().hasName("unsigned int")
and vbuf_855.getFunction() = func
and vlen_855.getFunction() = func
and vneedSize_856.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
