//! Hand-written convenience accessors for downstream consumers (semantic
//! layer, evaluator, Python bindings).

use crate::ast::*;

impl<'a> Body<'a> {
    pub fn attributes(&self) -> impl Iterator<Item = &Attribute<'a>> {
        self.items.iter().filter_map(|i| match i {
            BodyItem::Attribute(a) => Some(&**a),
            BodyItem::Block(_) => None,
        })
    }

    pub fn blocks(&self) -> impl Iterator<Item = &Block<'a>> {
        self.items.iter().filter_map(|i| match i {
            BodyItem::Block(b) => Some(&**b),
            BodyItem::Attribute(_) => None,
        })
    }

    /// First attribute named `name` (HCL forbids duplicates in valid input).
    pub fn find_attribute(&self, name: &str) -> Option<&Attribute<'a>> {
        self.attributes().find(|a| a.key.name == name)
    }

    /// All direct child blocks of type `ty` (e.g. every `ingress` block).
    pub fn blocks_of_type<'s>(&'s self, ty: &'s str) -> impl Iterator<Item = &'s Block<'a>> + 's {
        self.blocks().filter(move |b| b.ident.name == ty)
    }

    pub fn find_block(&self, ty: &str) -> Option<&Block<'a>> {
        self.blocks().find(|b| b.ident.name == ty)
    }
}

impl<'a> Block<'a> {
    /// The block type, e.g. `"resource"`.
    pub fn block_type(&self) -> &'a str {
        self.ident.name.as_str()
    }

    /// Label `i` as a string, e.g. `label(0) == Some("aws_s3_bucket")`.
    pub fn label(&self, i: usize) -> Option<&'a str> {
        self.labels.get(i).map(|l| l.value.as_str())
    }

    pub fn label_values(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.labels.iter().map(|l| l.value.as_str())
    }
}

impl<'a> Expression<'a> {
    /// Strips any number of surrounding parentheses.
    pub fn without_parens(&self) -> &Expression<'a> {
        let mut e = self;
        while let Expression::Parenthesized(p) = e {
            e = &p.expression;
        }
        e
    }

    /// The value of a quoted string without interpolation.
    pub fn as_string_literal(&self) -> Option<&'a str> {
        match self {
            Expression::String(s) => Some(s.value.as_str()),
            _ => None,
        }
    }

    /// For a reference like `var.x`, `aws_s3_bucket.b.id` or `local.a[0]`,
    /// the root name (`var`, `aws_s3_bucket`, `local`) and the operators
    /// that follow it. `None` if the expression is not rooted at a variable.
    pub fn as_reference(&self) -> Option<(&'a str, &[TraversalOperator<'a>])> {
        match self {
            Expression::Variable(v) => Some((v.name.as_str(), &[])),
            Expression::Traversal(t) => t.root_name().map(|r| (r, &t.operators[..])),
            _ => None,
        }
    }
}

impl<'a> Traversal<'a> {
    /// Root name if the traversal starts at a bare variable.
    pub fn root_name(&self) -> Option<&'a str> {
        match &self.object {
            Expression::Variable(v) => Some(v.name.as_str()),
            _ => None,
        }
    }

    /// Leading `.attr` names up to the first non-attribute operator:
    /// `aws_s3_bucket.b.id[0]` -> `["b", "id"]`.
    pub fn attr_path(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.operators.iter().map_while(|op| op.attr_name())
    }
}

impl<'a> TraversalOperator<'a> {
    /// `Some(name)` for `.name`.
    pub fn attr_name(&self) -> Option<&'a str> {
        match self {
            TraversalOperator::GetAttr(g) => Some(g.name.name.as_str()),
            _ => None,
        }
    }
}

impl<'a> ObjectKey<'a> {
    /// The key as a static string, for bare identifiers and plain strings.
    pub fn as_static_str(&self) -> Option<&'a str> {
        match self {
            ObjectKey::Identifier(i) => Some(i.name.as_str()),
            ObjectKey::Expression(e) => e.without_parens().as_string_literal(),
        }
    }
}

impl<'a> Object<'a> {
    /// First item whose key is statically `name`.
    pub fn find(&self, name: &str) -> Option<&Expression<'a>> {
        self.items.iter().find(|i| i.key.as_static_str() == Some(name)).map(|i| &i.value)
    }
}

impl<'a> FunctionCall<'a> {
    /// `"provider::aws::arn_parse"` style full name as owned string; for
    /// non-namespaced calls prefer `self.name.name`.
    pub fn full_name(&self) -> String {
        let mut s = String::new();
        for ns in self.namespace.iter() {
            s.push_str(&ns.name);
            s.push_str("::");
        }
        s.push_str(&self.name.name);
        s
    }
}

impl UnaryOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            UnaryOperator::Not => "!",
            UnaryOperator::Negate => "-",
        }
    }
}

impl BinaryOperator {
    pub fn as_str(self) -> &'static str {
        use BinaryOperator::*;
        match self {
            Or => "||",
            And => "&&",
            Equal => "==",
            NotEqual => "!=",
            Less => "<",
            LessEqual => "<=",
            Greater => ">",
            GreaterEqual => ">=",
            Add => "+",
            Subtract => "-",
            Multiply => "*",
            Divide => "/",
            Modulo => "%",
        }
    }

    /// HCL precedence; higher binds tighter. All binary operators are
    /// left-associative.
    pub fn precedence(self) -> u8 {
        use BinaryOperator::*;
        match self {
            Or => 1,
            And => 2,
            Equal | NotEqual => 3,
            Less | LessEqual | Greater | GreaterEqual => 4,
            Add | Subtract => 5,
            Multiply | Divide | Modulo => 6,
        }
    }
}
