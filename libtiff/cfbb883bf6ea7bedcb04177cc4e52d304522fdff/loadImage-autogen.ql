/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-loadImage
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/loadImage
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-loadImage CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_6(Parameter vdump_6054, Variable vscanlinesize_6065, LogicalAndExpr target_11, ExprStmt target_12, ExprStmt target_13) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vscanlinesize_6065
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="4294967295"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dump_info")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="infile"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="loadImage"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Attention: scanlinesize %lu is larger than UINT32_MAX.\nFollowing dump might be wrong."
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vscanlinesize_6065
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation().isBefore(target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_9(Parameter vdump_6054, Variable vscanlinesize_6065, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="infile"
		and target_9.getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dump_buffer")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vscanlinesize_6065
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanlinesize_6065
}

/*predicate func_10(Parameter vdump_6054, Variable vscanlinesize_6065, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="format"
		and target_10.getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dump_buffer")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="infile"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vscanlinesize_6065
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanlinesize_6065
}

*/
predicate func_11(Parameter vdump_6054, LogicalAndExpr target_11) {
		target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="infile"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="level"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_12(Parameter vdump_6054, Variable vscanlinesize_6065, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("dump_info")
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="infile"
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_12.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_12.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_12.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=""
		and target_12.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Stripsize: %u, Number of Strips: %u, Rows per Strip: %u, Scanline size: %u"
		and target_12.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_12.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_12.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_12.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vscanlinesize_6065
}

predicate func_13(Parameter vdump_6054, Variable vscanlinesize_6065, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("dump_buffer")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="infile"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_13.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_13.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_6054
		and target_13.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_13.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vscanlinesize_6065
		and target_13.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_13.getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_13.getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_13.getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanlinesize_6065
}

from Function func, Parameter vdump_6054, Variable vscanlinesize_6065, PointerFieldAccess target_9, LogicalAndExpr target_11, ExprStmt target_12, ExprStmt target_13
where
not func_6(vdump_6054, vscanlinesize_6065, target_11, target_12, target_13)
and func_9(vdump_6054, vscanlinesize_6065, target_9)
and func_11(vdump_6054, target_11)
and func_12(vdump_6054, vscanlinesize_6065, target_12)
and func_13(vdump_6054, vscanlinesize_6065, target_13)
and vdump_6054.getType().hasName("dump_opts *")
and vscanlinesize_6065.getType().hasName("uint32_t")
and vdump_6054.getFunction() = func
and vscanlinesize_6065.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
