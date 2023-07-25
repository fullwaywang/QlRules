/**
 * @name libzip-9b46957ec98d85a572e9ef98301247f39338a3b5-_zip_read_eocd64
 * @id cpp/libzip/9b46957ec98d85a572e9ef98301247f39338a3b5/-zip-read-eocd64
 * @description libzip-9b46957ec98d85a572e9ef98301247f39338a3b5-lib/zip_open.c-_zip_read_eocd64 CVE-2017-14107
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_offset_730, Variable voffset_733, Variable veocd_offset_735, Variable vsize_736, BlockStmt target_4, LogicalAndExpr target_5, LogicalOrExpr target_6, LogicalAndExpr target_7) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_733
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_736
		and target_0.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuf_offset_730
		and target_0.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=veocd_offset_735
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbuf_offset_730, Parameter vflags_730, Parameter verror_730, Variable voffset_733, Variable veocd_offset_735, Variable vsize_736, LogicalAndExpr target_8, ExprStmt target_9, EqualityOperation target_10, ExprStmt target_11, LogicalAndExpr target_5, LogicalAndExpr target_7, ExprStmt target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_730
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_733
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_736
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuf_offset_730
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=veocd_offset_735
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zip_error_set")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verror_730
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="21"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(34)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(34).getFollowingStmt()=target_1)
		and target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vbuf_offset_730, Variable veocd_offset_735, LogicalAndExpr target_5, LogicalAndExpr target_7) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vbuf_offset_730
		and target_2.getAnOperand().(VariableAccess).getTarget()=veocd_offset_735
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable veocd_offset_735, VariableAccess target_3) {
		target_3.getTarget()=veocd_offset_735
}

predicate func_4(Parameter verror_730, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zip_error_set")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verror_730
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="21"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(Parameter vbuf_offset_730, Parameter vflags_730, Variable veocd_offset_735, Variable vsize_736, LogicalAndExpr target_5) {
		target_5.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_730
		and target_5.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_736
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=veocd_offset_735
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuf_offset_730
}

predicate func_6(Variable voffset_733, Variable vsize_736, LogicalOrExpr target_6) {
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_733
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9223372036854775807"
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_733
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_736
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_733
}

predicate func_7(Parameter vflags_730, Variable voffset_733, Variable veocd_offset_735, Variable vsize_736, LogicalAndExpr target_7) {
		target_7.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_730
		and target_7.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_733
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_736
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veocd_offset_735
}

predicate func_8(Parameter vflags_730, LogicalAndExpr target_8) {
		target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_730
		and target_8.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_9(Parameter verror_730, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("zip_error_set")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verror_730
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="21"
		and target_9.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_10(Parameter verror_730, EqualityOperation target_10) {
		target_10.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_zip_cdir_new")
		and target_10.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=verror_730
		and target_10.getAnOperand().(Literal).getValue()="0"
}

predicate func_11(Variable voffset_733, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="offset"
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffset_733
}

predicate func_12(Variable vsize_736, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_736
}

from Function func, Parameter vbuf_offset_730, Parameter vflags_730, Parameter verror_730, Variable voffset_733, Variable veocd_offset_735, Variable vsize_736, VariableAccess target_3, BlockStmt target_4, LogicalAndExpr target_5, LogicalOrExpr target_6, LogicalAndExpr target_7, LogicalAndExpr target_8, ExprStmt target_9, EqualityOperation target_10, ExprStmt target_11, ExprStmt target_12
where
not func_0(vbuf_offset_730, voffset_733, veocd_offset_735, vsize_736, target_4, target_5, target_6, target_7)
and not func_1(vbuf_offset_730, vflags_730, verror_730, voffset_733, veocd_offset_735, vsize_736, target_8, target_9, target_10, target_11, target_5, target_7, target_12, func)
and func_3(veocd_offset_735, target_3)
and func_4(verror_730, target_4)
and func_5(vbuf_offset_730, vflags_730, veocd_offset_735, vsize_736, target_5)
and func_6(voffset_733, vsize_736, target_6)
and func_7(vflags_730, voffset_733, veocd_offset_735, vsize_736, target_7)
and func_8(vflags_730, target_8)
and func_9(verror_730, target_9)
and func_10(verror_730, target_10)
and func_11(voffset_733, target_11)
and func_12(vsize_736, target_12)
and vbuf_offset_730.getType().hasName("zip_uint64_t")
and vflags_730.getType().hasName("unsigned int")
and verror_730.getType().hasName("zip_error_t *")
and voffset_733.getType().hasName("zip_uint64_t")
and veocd_offset_735.getType().hasName("zip_uint64_t")
and vsize_736.getType().hasName("zip_uint64_t")
and vbuf_offset_730.getParentScope+() = func
and vflags_730.getParentScope+() = func
and verror_730.getParentScope+() = func
and voffset_733.getParentScope+() = func
and veocd_offset_735.getParentScope+() = func
and vsize_736.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
