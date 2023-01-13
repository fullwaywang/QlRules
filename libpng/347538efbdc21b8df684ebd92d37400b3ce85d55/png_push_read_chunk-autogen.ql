/**
 * @name libpng-347538efbdc21b8df684ebd92d37400b3ce85d55-png_push_read_chunk
 * @id cpp/libpng/347538efbdc21b8df684ebd92d37400b3ce85d55/png-push-read-chunk
 * @description libpng-347538efbdc21b8df684ebd92d37400b3ce85d55-png_push_read_chunk CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vchunk_name_169) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchunk_name_169
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="1229209940")
}

predicate func_1(Variable vchunk_name_169, Parameter vpng_ptr_167) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user_chunk_malloc_max"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchunk_name_169
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="1229209940")
}

predicate func_2(Variable vchunk_name_169, Parameter vpng_ptr_167) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="push_length"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("png_alloc_size_t")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_chunk_error")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunk data is too large"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchunk_name_169
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="1229209940")
}

predicate func_3(Parameter vpng_ptr_167) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("png_benign_error")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167
		and target_3.getArgument(1).(StringLiteral).getValue()="Too many IDATs found")
}

predicate func_4(Parameter vpng_ptr_167) {
    exists(FunctionCall target_4 |
        target_4.getTarget().hasName("png_check_chunk_length")
        and target_4.getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167)
}

from Function func, Variable vchunk_name_169, Parameter vpng_ptr_167
where
not func_0(vchunk_name_169)
and not func_1(vchunk_name_169, vpng_ptr_167)
and not func_2(vchunk_name_169, vpng_ptr_167)
and vchunk_name_169.getType().hasName("png_uint_32")
and vpng_ptr_167.getType().hasName("png_structrp")
and func_3(vpng_ptr_167)
and not func_4(vpng_ptr_167)
and vchunk_name_169.getParentScope+() = func
and vpng_ptr_167.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
