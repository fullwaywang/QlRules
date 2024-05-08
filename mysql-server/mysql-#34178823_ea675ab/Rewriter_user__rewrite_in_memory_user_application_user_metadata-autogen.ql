/**
 * @name mysql-server-ea675ab09efcea100f96d1114fef6d13c0a2b0de-Rewriter_user__rewrite_in_memory_user_application_user_metadata
 * @id cpp/mysql-server/ea675ab09efcea100f96d1114fef6d13c0a2b0de/rewriteruserrewriteinmemoryuserapplicationusermetadata
 * @description mysql-server-ea675ab09efcea100f96d1114fef6d13c0a2b0de-sql/sql_rewrite.cc-Rewriter_user__rewrite_in_memory_user_application_user_metadata mysql-#34178823
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
	target_0.getValue()=" ATTRIBUTE '"
	and not target_0.getValue()=" ATTRIBUTE "
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
	target_1.getValue()=" COMMENT '"
	and not target_1.getValue()=" COMMENT "
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vlex_458, ConstructorCall target_2) {
	exists(PointerFieldAccess obj_0 | obj_0=target_2.getArgument(0) |
		obj_0.getTarget().getName()="alter_user_comment_text"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vlex_458
	)
}

predicate func_3(Parameter vlex_458) {
exists(ValueFieldAccess target_3 |
	exists(PointerFieldAccess obj_0 | obj_0=target_3.getQualifier() |
		obj_0.getTarget().getName()="alter_user_comment_text"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vlex_458
	)
	and target_3.getTarget().getName()="str"
)
}

predicate func_4(Parameter vlex_458, EqualityOperation target_12, ConstructorCall target_2) {
exists(ValueFieldAccess target_4 |
	exists(PointerFieldAccess obj_0 | obj_0=target_4.getQualifier() |
		obj_0.getTarget().getName()="alter_user_comment_text"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vlex_458
	)
	and target_4.getTarget().getName()="length"
	and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_6(Parameter vstr_458, ExprStmt target_11) {
exists(FunctionCall target_6 |
	exists(PointerFieldAccess obj_0 | obj_0=target_6.getArgument(0) |
		obj_0.getTarget().getName()="m_thd"
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and exists(VariableAccess obj_1 | obj_1=target_6.getArgument(3) |
		obj_1.getTarget()=vstr_458
		and obj_1.getLocation().isBefore(target_11.getExpr().(FunctionCall).getQualifier().(VariableAccess).getLocation())
	)
	and target_6.getTarget().hasName("append_query_string")
	and target_6.getArgument(1).(VariableAccess).getType().hasName("CHARSET_INFO *")
	and target_6.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("String")
)
}

predicate func_8(Parameter vlex_458, PointerFieldAccess target_8) {
	target_8.getTarget().getName()="alter_user_comment_text"
	and target_8.getQualifier().(VariableAccess).getTarget()=vlex_458
	and target_8.getParent().(ConstructorCall).getParent().(FunctionCall).getArgument(0) instanceof ConstructorCall
}

predicate func_9(Parameter vstr_458, VariableAccess target_9) {
	target_9.getTarget()=vstr_458
}

predicate func_10(Parameter vstr_458, FunctionCall target_10) {
	target_10.getTarget().hasName("append")
	and target_10.getQualifier().(VariableAccess).getTarget()=vstr_458
	and target_10.getArgument(0) instanceof ConstructorCall
}

predicate func_11(Parameter vstr_458, EqualityOperation target_12, ExprStmt target_11) {
	exists(FunctionCall obj_0 | obj_0=target_11.getExpr() |
		obj_0.getTarget().hasName("append")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vstr_458
		and obj_0.getArgument(0).(ConstructorCall).getArgument(0).(StringLiteral).getValue()="'"
	)
	and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_12(Parameter vlex_458, EqualityOperation target_12) {
	exists(PointerFieldAccess obj_0 | obj_0=target_12.getLeftOperand() |
		obj_0.getTarget().getName()="alter_user_attribute"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vlex_458
	)
}

from Function func, Parameter vlex_458, Parameter vstr_458, StringLiteral target_0, StringLiteral target_1, ConstructorCall target_2, PointerFieldAccess target_8, VariableAccess target_9, FunctionCall target_10, ExprStmt target_11, EqualityOperation target_12
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vlex_458, target_2)
and not func_3(vlex_458)
and not func_4(vlex_458, target_12, target_2)
and not func_6(vstr_458, target_11)
and func_8(vlex_458, target_8)
and func_9(vstr_458, target_9)
and func_10(vstr_458, target_10)
and func_11(vstr_458, target_12, target_11)
and func_12(vlex_458, target_12)
and vlex_458.getType().hasName("const LEX *")
and vstr_458.getType().hasName("String *")
and vlex_458.getFunction() = func
and vstr_458.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
