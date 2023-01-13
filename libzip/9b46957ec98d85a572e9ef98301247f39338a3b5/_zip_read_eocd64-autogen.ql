/**
 * @name libzip-9b46957ec98d85a572e9ef98301247f39338a3b5-_zip_read_eocd64
 * @id cpp/libzip/9b46957ec98d85a572e9ef98301247f39338a3b5/-zip-read-eocd64
 * @description libzip-9b46957ec98d85a572e9ef98301247f39338a3b5-_zip_read_eocd64 CVE-2017-14107
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_offset_730, Parameter verror_730, Variable veocd_offset_735) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand() instanceof AddExpr
		and target_0.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbuf_offset_730
		and target_0.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=veocd_offset_735
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zip_error_set")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verror_730
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="21"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter vbuf_offset_730, Parameter vflags_730, Parameter verror_730, Variable voffset_733, Variable veocd_offset_735, Variable vsize_736, Function func) {
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
		and (func.getEntryPoint().(BlockStmt).getStmt(34)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(34).getFollowingStmt()=target_1))
}

predicate func_6(Variable voffset_733, Variable vsize_736) {
	exists(AddExpr target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=voffset_733
		and target_6.getAnOperand().(VariableAccess).getTarget()=vsize_736)
}

predicate func_8(Parameter vbuf_offset_730, Variable veocdloc_offset_736) {
	exists(AddExpr target_8 |
		target_8.getAnOperand().(VariableAccess).getTarget()=vbuf_offset_730
		and target_8.getAnOperand().(VariableAccess).getTarget()=veocdloc_offset_736)
}

predicate func_9(Parameter verror_730) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("zip_error_set")
		and target_9.getArgument(0).(VariableAccess).getTarget()=verror_730
		and target_9.getArgument(1).(Literal).getValue()="21"
		and target_9.getArgument(2).(Literal).getValue()="0")
}

predicate func_10(Parameter verror_730, Variable voffset_733, Variable vsize_736) {
	exists(RelationalOperation target_10 |
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_733
		and target_10.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_736
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=voffset_733
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_733
		and target_10.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9223372036854775807"
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zip_error_set")
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verror_730
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="27"
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_11(Variable veocd_offset_735, Variable vsize_736) {
	exists(AddExpr target_11 |
		target_11.getAnOperand().(VariableAccess).getTarget()=vsize_736
		and target_11.getAnOperand().(VariableAccess).getTarget()=veocd_offset_735)
}

from Function func, Parameter vbuf_offset_730, Parameter vflags_730, Parameter verror_730, Variable voffset_733, Variable veocd_offset_735, Variable vsize_736, Variable veocdloc_offset_736
where
not func_0(vbuf_offset_730, verror_730, veocd_offset_735)
and not func_1(vbuf_offset_730, vflags_730, verror_730, voffset_733, veocd_offset_735, vsize_736, func)
and func_6(voffset_733, vsize_736)
and vbuf_offset_730.getType().hasName("zip_uint64_t")
and func_8(vbuf_offset_730, veocdloc_offset_736)
and vflags_730.getType().hasName("unsigned int")
and verror_730.getType().hasName("zip_error_t *")
and func_9(verror_730)
and voffset_733.getType().hasName("zip_uint64_t")
and func_10(verror_730, voffset_733, vsize_736)
and veocd_offset_735.getType().hasName("zip_uint64_t")
and func_11(veocd_offset_735, vsize_736)
and vsize_736.getType().hasName("zip_uint64_t")
and veocdloc_offset_736.getType().hasName("zip_uint64_t")
and vbuf_offset_730.getParentScope+() = func
and vflags_730.getParentScope+() = func
and verror_730.getParentScope+() = func
and voffset_733.getParentScope+() = func
and veocd_offset_735.getParentScope+() = func
and vsize_736.getParentScope+() = func
and veocdloc_offset_736.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
