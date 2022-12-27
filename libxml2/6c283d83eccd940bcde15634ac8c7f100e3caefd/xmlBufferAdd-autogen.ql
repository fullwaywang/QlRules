/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferAdd
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufferAdd
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferAdd CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_7577, Parameter vlen_7577) {
	exists(Literal target_0 |
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_7577)
}

predicate func_3(Parameter vbuf_7577, Variable vneedSize_7578) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="size"
		and target_3.getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_3.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vneedSize_7578
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlBufferResize")
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_7577
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vneedSize_7578
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlTreeErrMemory")
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="growing buffer")
}

predicate func_4(Parameter vbuf_7577, Variable vneedSize_7578) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vneedSize_7578
		and target_4.getLesserOperand() instanceof PointerFieldAccess
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlBufferResize")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_7577
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vneedSize_7578
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlTreeErrMemory")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="growing buffer")
}

predicate func_5(Parameter vbuf_7577) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="use"
		and target_5.getQualifier().(VariableAccess).getTarget()=vbuf_7577)
}

predicate func_7(Parameter vbuf_7577, Parameter vlen_7577) {
	exists(AddExpr target_7 |
		target_7.getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7577
		and target_7.getAnOperand().(VariableAccess).getTarget()=vlen_7577)
}

from Function func, Parameter vbuf_7577, Parameter vlen_7577, Variable vneedSize_7578
where
func_0(vbuf_7577, vlen_7577)
and func_3(vbuf_7577, vneedSize_7578)
and func_4(vbuf_7577, vneedSize_7578)
and vbuf_7577.getType().hasName("xmlBufferPtr")
and func_5(vbuf_7577)
and vlen_7577.getType().hasName("int")
and func_7(vbuf_7577, vlen_7577)
and vneedSize_7578.getType().hasName("unsigned int")
and vbuf_7577.getParentScope+() = func
and vlen_7577.getParentScope+() = func
and vneedSize_7578.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
