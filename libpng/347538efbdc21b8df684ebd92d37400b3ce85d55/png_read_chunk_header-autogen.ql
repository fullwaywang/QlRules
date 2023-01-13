/**
 * @name libpng-347538efbdc21b8df684ebd92d37400b3ce85d55-png_read_chunk_header
 * @id cpp/libpng/347538efbdc21b8df684ebd92d37400b3ce85d55/png-read-chunk-header
 * @description libpng-347538efbdc21b8df684ebd92d37400b3ce85d55-png_read_chunk_header CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_156, Variable vlength_159, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="1229209940"
		and target_0.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_156
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_159
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_4(Parameter vpng_ptr_156) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="chunk_name"
		and target_4.getQualifier().(VariableAccess).getTarget()=vpng_ptr_156)
}

predicate func_5(Parameter vpng_ptr_156, Variable vbuf_158, Variable vlength_159) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vlength_159
		and target_5.getRValue().(FunctionCall).getTarget().hasName("png_get_uint_31")
		and target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156
		and target_5.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_158)
}

predicate func_6(Parameter vpng_ptr_156) {
    exists(FunctionCall target_4 |
        target_4.getTarget().hasName("png_check_chunk_length")
        and target_4.getArgument(0).(VariableAccess).getTarget()=vpng_ptr_156)
}

from Function func, Parameter vpng_ptr_156, Variable vbuf_158, Variable vlength_159
where
not func_0(vpng_ptr_156, vlength_159, func)
and vpng_ptr_156.getType().hasName("png_structrp")
and func_4(vpng_ptr_156)
and vlength_159.getType().hasName("png_uint_32")
and func_5(vpng_ptr_156, vbuf_158, vlength_159)
and not func_6(vpng_ptr_156)
and vpng_ptr_156.getParentScope+() = func
and vbuf_158.getParentScope+() = func
and vlength_159.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
