/**
 * @name libssh2-ff1b155731ff8f790f12d980911d9fd84d0e1598-_libssh2_check_length
 * @id cpp/libssh2/ff1b155731ff8f790f12d980911d9fd84d0e1598/-libssh2-check-length
 * @description libssh2-ff1b155731ff8f790f12d980911d9fd84d0e1598-src/misc.c-_libssh2_check_length CVE-2019-13115
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_812, VariableAccess target_0) {
		target_0.getTarget()=vlen_812
}

predicate func_2(Parameter vbuf_812, Parameter vlen_812, ConditionalExpr target_8) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_812
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vbuf_812, Parameter vlen_812, ReturnStmt target_10, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="len"
		and target_3.getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_3.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vlen_812
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_10
}

*/
predicate func_4(Parameter vbuf_812, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="data"
		and target_4.getQualifier().(VariableAccess).getTarget()=vbuf_812
}

predicate func_5(Parameter vbuf_812, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="len"
		and target_5.getQualifier().(VariableAccess).getTarget()=vbuf_812
}

/*predicate func_6(Parameter vbuf_812, Parameter vlen_812, ReturnStmt target_10, VariableAccess target_6) {
		target_6.getTarget()=vlen_812
		and target_6.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_6.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_6.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_10
}

*/
predicate func_7(Parameter vbuf_812, Parameter vlen_812, Function func, IfStmt target_7) {
		target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_812
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_7.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Parameter vbuf_812, Parameter vlen_812, ConditionalExpr target_8) {
		target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dataptr"
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_812
		and target_8.getThen().(Literal).getValue()="1"
		and target_8.getElse().(Literal).getValue()="0"
}

/*predicate func_9(Parameter vbuf_812, Parameter vlen_812, SubExpr target_9) {
		target_9.getLeftOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_9.getRightOperand().(VariableAccess).getTarget()=vlen_812
		and target_9.getParent().(LEExpr).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dataptr"
		and target_9.getParent().(LEExpr).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
		and target_9.getParent().(LEExpr).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getParent().(LEExpr).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_812
}

*/
predicate func_10(ReturnStmt target_10) {
		target_10.getExpr() instanceof Literal
}

from Function func, Parameter vbuf_812, Parameter vlen_812, VariableAccess target_0, PointerFieldAccess target_4, PointerFieldAccess target_5, IfStmt target_7, ConditionalExpr target_8, ReturnStmt target_10
where
func_0(vlen_812, target_0)
and not func_2(vbuf_812, vlen_812, target_8)
and func_4(vbuf_812, target_4)
and func_5(vbuf_812, target_5)
and func_7(vbuf_812, vlen_812, func, target_7)
and func_8(vbuf_812, vlen_812, target_8)
and func_10(target_10)
and vbuf_812.getType().hasName("string_buf *")
and vlen_812.getType().hasName("size_t")
and vbuf_812.getParentScope+() = func
and vlen_812.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
