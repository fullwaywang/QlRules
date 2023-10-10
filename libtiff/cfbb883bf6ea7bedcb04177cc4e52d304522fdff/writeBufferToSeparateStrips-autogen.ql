/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-writeBufferToSeparateStrips
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/writeBufferToSeparateStrips
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-writeBufferToSeparateStrips CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrowstripsize_1194, ExprStmt target_5, ExprStmt target_6) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrowstripsize_1194
		and target_0.getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrowstripsize_1194
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vrowstripsize_1194, ExprStmt target_7) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vrowstripsize_1194
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("tdata_t")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrowstripsize_1194
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdump_1185, Variable vscanlinesize_1194, LogicalAndExpr target_8, ExprStmt target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vscanlinesize_1194
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="4294967295"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dump_info")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="infile"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_1185
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_1185
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="loadImage"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Attention: scanlinesize %lu is larger than UINT32_MAX.\nFollowing dump might be wrong."
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vscanlinesize_1194
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vrowstripsize_1194, VariableAccess target_3) {
		target_3.getTarget()=vrowstripsize_1194
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_4(Variable vrowstripsize_1194, VariableAccess target_4) {
		target_4.getTarget()=vrowstripsize_1194
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("tdata_t")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
}

predicate func_5(Variable vrowstripsize_1194, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrowstripsize_1194
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_6(Variable vrowstripsize_1194, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("tdata_t")
		and target_6.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrowstripsize_1194
}

predicate func_7(Variable vrowstripsize_1194, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tdata_t")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrowstripsize_1194
}

predicate func_8(Parameter vdump_1185, LogicalAndExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="outfile"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_1185
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="level"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_1185
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_9(Parameter vdump_1185, Variable vscanlinesize_1194, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("dump_info")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="outfile"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_1185
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_1185
		and target_9.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=""
		and target_9.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Sample %2d, Strip: %2d, bytes: %4d, Row %4d, bytes: %4d, Input offset: %6d"
		and target_9.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("tsample_t")
		and target_9.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getExpr().(FunctionCall).getArgument(5).(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("tstrip_t")
		and target_9.getExpr().(FunctionCall).getArgument(5).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_9.getExpr().(FunctionCall).getArgument(7).(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_9.getExpr().(FunctionCall).getArgument(7).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vscanlinesize_1194
		and target_9.getExpr().(FunctionCall).getArgument(9).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_9.getExpr().(FunctionCall).getArgument(9).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint8_t *")
}

from Function func, Parameter vdump_1185, Variable vrowstripsize_1194, Variable vscanlinesize_1194, VariableAccess target_3, VariableAccess target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, LogicalAndExpr target_8, ExprStmt target_9
where
not func_0(vrowstripsize_1194, target_5, target_6)
and not func_1(vrowstripsize_1194, target_7)
and not func_2(vdump_1185, vscanlinesize_1194, target_8, target_9)
and func_3(vrowstripsize_1194, target_3)
and func_4(vrowstripsize_1194, target_4)
and func_5(vrowstripsize_1194, target_5)
and func_6(vrowstripsize_1194, target_6)
and func_7(vrowstripsize_1194, target_7)
and func_8(vdump_1185, target_8)
and func_9(vdump_1185, vscanlinesize_1194, target_9)
and vdump_1185.getType().hasName("dump_opts *")
and vrowstripsize_1194.getType().hasName("tsize_t")
and vscanlinesize_1194.getType().hasName("tsize_t")
and vdump_1185.getFunction() = func
and vrowstripsize_1194.(LocalVariable).getFunction() = func
and vscanlinesize_1194.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
