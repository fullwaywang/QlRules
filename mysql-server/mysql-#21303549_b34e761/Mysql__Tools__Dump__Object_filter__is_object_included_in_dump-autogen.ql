/**
 * @name mysql-server-b34e761fce136ec9be0ddebd6ff8892c8428a26f-Mysql__Tools__Dump__Object_filter__is_object_included_in_dump
 * @id cpp/mysql-server/b34e761fce136ec9be0ddebd6ff8892c8428a26f/mysqltoolsdumpobjectfilterisobjectincludedindump
 * @description mysql-server-b34e761fce136ec9be0ddebd6ff8892c8428a26f-client/dump/object_filter.cc-Mysql__Tools__Dump__Object_filter__is_object_included_in_dump mysql-#21303549
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vobject_200, BlockStmt target_2, FunctionCall target_3, EqualityOperation target_1) {
exists(LogicalOrExpr target_0 |
	exists(EqualityOperation obj_0 | obj_0=target_0.getRightOperand() |
		obj_0.getLeftOperand().(VariableAccess).getTarget()=vobject_200
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and target_0.getLeftOperand() instanceof EqualityOperation
	and target_0.getParent().(IfStmt).getThen()=target_2
	and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getLocation())
	and target_0.getRightOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation())
)
}

predicate func_1(Parameter vobject_200, BlockStmt target_2, EqualityOperation target_1) {
	target_1.getLeftOperand().(VariableAccess).getTarget()=vobject_200
	and target_1.getRightOperand().(Literal).getValue()="0"
	and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Function func, BlockStmt target_2) {
	exists(ExprStmt obj_0 | obj_0=target_2.getStmt(0) |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			exists(AddressOfExpr obj_2 | obj_2=obj_1.getRValue() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getOperand() |
					obj_3.getTarget().getName()="m_tables_included"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
			)
			and obj_1.getLValue().(VariableAccess).getTarget().getType().hasName("vector<pair<basic_string<char, char_traits<char>, allocator<char>>, basic_string<char, char_traits<char>, allocator<char>>>, allocator<pair<basic_string<char, char_traits<char>, allocator<char>>, basic_string<char, char_traits<char>, allocator<char>>>>> *")
		)
	)
	and exists(ExprStmt obj_4 | obj_4=target_2.getStmt(1) |
		exists(AssignExpr obj_5 | obj_5=obj_4.getExpr() |
			exists(AddressOfExpr obj_6 | obj_6=obj_5.getRValue() |
				exists(PointerFieldAccess obj_7 | obj_7=obj_6.getOperand() |
					obj_7.getTarget().getName()="m_tables_excluded"
					and obj_7.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
			)
			and obj_5.getLValue().(VariableAccess).getTarget().getType().hasName("vector<pair<basic_string<char, char_traits<char>, allocator<char>>, basic_string<char, char_traits<char>, allocator<char>>>, allocator<pair<basic_string<char, char_traits<char>, allocator<char>>, basic_string<char, char_traits<char>, allocator<char>>>>> *")
		)
	)
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vobject_200, FunctionCall target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(NotExpr obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getOperand() |
				exists(AddressOfExpr obj_3 | obj_3=obj_2.getArgument(2) |
					exists(PointerFieldAccess obj_4 | obj_4=obj_3.getOperand() |
						obj_4.getTarget().getName()="m_databases_included"
						and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
				)
				and exists(AddressOfExpr obj_5 | obj_5=obj_2.getArgument(3) |
					exists(PointerFieldAccess obj_6 | obj_6=obj_5.getOperand() |
						obj_6.getTarget().getName()="m_databases_excluded"
						and obj_6.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
				)
				and obj_2.getTarget().hasName("is_object_included_by_lists")
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
				and obj_2.getArgument(0).(ConstructorCall).getArgument(0).(StringLiteral).getValue()=""
			)
		)
	)
	and target_3.getTarget().hasName("get_schema")
	and target_3.getQualifier().(VariableAccess).getTarget()=vobject_200
}

from Function func, Parameter vobject_200, EqualityOperation target_1, BlockStmt target_2, FunctionCall target_3
where
not func_0(vobject_200, target_2, target_3, target_1)
and func_1(vobject_200, target_2, target_1)
and func_2(func, target_2)
and func_3(vobject_200, target_3)
and vobject_200.getType().hasName("Abstract_data_object *")
and vobject_200.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
